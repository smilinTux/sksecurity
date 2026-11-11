"""Tests for sksecurity.filescreen and the screen-file CLI."""

import json
import shutil
import zipfile

import pytest
from click.testing import CliRunner

from sksecurity import filescreen
from sksecurity.cli import cli
from sksecurity.email_screener import Verdict


@pytest.fixture(autouse=True)
def no_av(monkeypatch, request):
    if request.node.name.startswith(("test_av_scan", "test_eicar")):
        return
    monkeypatch.setattr(filescreen, "av_scan", lambda p: ("unavailable", None))
    monkeypatch.setattr(filescreen, "av_scan_batch", lambda ps: ("unavailable", {}))


def mk(tmp_path, name, data=b"hello"):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def eicar() -> bytes:
    # Built at runtime so no literal signature is committed.
    return (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!" + "$H+H*").encode()


def test_clean_text_safe_and_av_unavailable(tmp_path):
    v = filescreen.screen_file(mk(tmp_path, "notes.txt"))
    assert v.verdict == Verdict.SAFE
    assert v.av == "unavailable" and v.metadata["note"] == "av unavailable"


def test_dangerous_extension_malicious(tmp_path):
    assert filescreen.screen_file(mk(tmp_path, "setup.exe", b"MZ" + b"\0" * 50)).is_malicious


def test_double_extension_malicious(tmp_path):
    assert filescreen.screen_file(mk(tmp_path, "invoice.pdf.exe")).is_malicious


def test_pe_named_pdf_malicious(tmp_path):
    v = filescreen.screen_file(mk(tmp_path, "report.pdf", b"MZ" + b"\0" * 100))
    assert v.is_malicious
    assert any("PE" in f.description for f in v.findings)


def test_elf_named_pdf_malicious(tmp_path):
    v = filescreen.screen_file(mk(tmp_path, "report.pdf", b"\x7fELF" + b"\0" * 100))
    assert v.is_malicious


def test_real_pdf_header_safe(tmp_path):
    assert filescreen.screen_file(mk(tmp_path, "a.pdf", b"%PDF-1.7\n")).verdict == Verdict.SAFE


def test_ooxml_with_vba_flagged(tmp_path):
    p = tmp_path / "m.docm"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("[Content_Types].xml", "<x/>")
        z.writestr("word/vbaProject.bin", b"x")
    v = filescreen.screen_file(str(p))
    assert v.verdict == Verdict.SUSPICIOUS
    assert any("VBA" in f.description for f in v.findings)


def test_plain_docx_safe(tmp_path):
    p = tmp_path / "ok.docx"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("[Content_Types].xml", "<x/>")
        z.writestr("word/document.xml", "<d/>")
    assert filescreen.screen_file(str(p)).verdict == Verdict.SAFE


def test_ole_doc_medium(tmp_path):
    v = filescreen.screen_file(mk(tmp_path, "old.doc", bytes.fromhex("D0CF11E0A1B11AE1") + b"\0" * 64))
    assert v.verdict == Verdict.SUSPICIOUS
    assert v.findings[0].severity == "MEDIUM"
    assert "macros" in v.findings[0].description


def test_zip_members_extension_rules_without_extracting(tmp_path):
    p = tmp_path / "bundle.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("readme.txt", "hi")
        z.writestr("payload/run.exe", "x")
    before = sorted(x.name for x in tmp_path.iterdir())
    v = filescreen.screen_file(str(p))
    assert v.is_malicious
    assert any(f.description.startswith("Archive member") for f in v.findings)
    assert sorted(x.name for x in tmp_path.iterdir()) == before


def test_clean_zip_safe(tmp_path):
    p = tmp_path / "ok.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("a.txt", "hi")
    assert filescreen.screen_file(str(p)).verdict == Verdict.SAFE


def test_encrypted_zip_medium(tmp_path):
    p = tmp_path / "enc.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("a.txt", "hi")
    raw = bytearray(p.read_bytes())
    # set the encrypted bit (bit 0) in local and central headers
    for sig in (b"PK\x03\x04", b"PK\x01\x02"):
        i = raw.find(sig)
        off = i + (6 if sig == b"PK\x03\x04" else 8)
        raw[off] |= 1
    p.write_bytes(bytes(raw))
    v = filescreen.screen_file(str(p))
    assert v.verdict == Verdict.SUSPICIOUS
    assert any("Encrypted" in f.description for f in v.findings)


def test_av_hit_is_malicious(tmp_path, monkeypatch):
    monkeypatch.setattr(filescreen, "av_scan", lambda p: ("clamscan", "Test.Sig-1"))
    v = filescreen.screen_file(mk(tmp_path, "a.txt"))
    assert v.is_malicious and v.av == "clamscan"
    assert "Test.Sig-1" in v.findings[0].description


def test_av_scan_parses_clamscan(monkeypatch):
    class P:
        returncode = 1
        stdout = "/x/f: Win.Test.EICAR_HDB-1 FOUND\n"
    monkeypatch.setattr(filescreen.shutil, "which", lambda n: "/usr/bin/clamscan" if n == "clamscan" else None)
    monkeypatch.setattr(filescreen.subprocess, "run", lambda *a, **k: P())
    assert filescreen.av_scan("/x/f") == ("clamscan", "Win.Test.EICAR_HDB-1")


def test_screen_files_single_av_pass(tmp_path, monkeypatch):
    calls = []

    def batch(paths):
        calls.append(list(paths))
        return "clamscan", {paths[1]: "Sig.X"}
    monkeypatch.setattr(filescreen, "av_scan_batch", batch)
    a, b = mk(tmp_path, "a.txt"), mk(tmp_path, "b.txt")
    res = filescreen.screen_files([a, b])
    assert len(calls) == 1
    assert [r.verdict.value for r in res] == ["safe", "malicious"]


def test_av_scan_none_installed(monkeypatch):
    monkeypatch.setattr(filescreen.shutil, "which", lambda n: None)
    assert filescreen.av_scan("/x") == ("unavailable", None)


def test_av_scan_prefers_clamdscan_with_socket(monkeypatch):
    seen = []

    class P:
        returncode = 0
        stdout = ""

    def run(cmd, **k):
        seen.append(cmd[0])
        return P()
    monkeypatch.setattr(filescreen.shutil, "which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(filescreen, "_clamd_socket_exists", lambda: True)
    monkeypatch.setattr(filescreen.subprocess, "run", run)
    assert filescreen.av_scan("/x") == ("clamdscan", None)
    assert seen == ["clamdscan"]


def test_unreadable_file_not_safe(tmp_path):
    assert filescreen.screen_file(str(tmp_path / "missing.bin")).verdict != Verdict.SAFE


@pytest.mark.skipif(not shutil.which("clamscan"), reason="clamscan not installed")
def test_eicar_detected_by_clamscan(tmp_path):
    p = mk(tmp_path, "t.txt", eicar())
    v = filescreen.screen_file(p)
    assert v.av == "clamscan" and v.is_malicious
    assert (tmp_path / "t.txt").exists()  # never deleted


def test_file_never_modified(tmp_path):
    p = mk(tmp_path, "keep.exe", b"MZ" + b"\0" * 10)
    import os
    st = os.stat(p)
    filescreen.screen_file(p)
    assert open(p, "rb").read() == b"MZ" + b"\0" * 10
    assert os.stat(p).st_mtime_ns == st.st_mtime_ns


def test_cli_exit_codes_and_json(tmp_path):
    good = mk(tmp_path, "a.txt")
    bad = mk(tmp_path, "b.pdf.exe")
    r = CliRunner().invoke(cli, ["screen-file", good])
    assert r.exit_code == 0
    r = CliRunner().invoke(cli, ["screen-file", good, bad, "--format", "json"])
    assert r.exit_code == 1
    data = json.loads(r.output)
    assert [f["verdict"] for f in data["files"]] == ["safe", "malicious"]
