import json
import os
import zipfile
from email.message import EmailMessage

import pytest
from click.testing import CliRunner

from sksecurity import filescreen
from sksecurity.cli import cli
from sksecurity.sweeps import get
from sksecurity.sweeps import mail


@pytest.fixture(autouse=True)
def no_av(monkeypatch):
    monkeypatch.setattr(filescreen, "av_scan_batch", lambda ps: ("unavailable", {}))
    monkeypatch.setattr(filescreen, "av_scan", lambda p: ("unavailable", None))


def snapshot(d):
    out = {}
    for root, _, fs in os.walk(d):
        for f in fs:
            p = os.path.join(root, f)
            out[p] = (open(p, "rb").read(), os.stat(p).st_mtime_ns)
    return out


def eml(path, body, subject="Hi", attach=None, msgid="<m1@example.org>"):
    m = EmailMessage()
    m["From"] = "a@example.org"
    m["To"] = "b@example.org"
    m["Subject"] = subject
    m["Message-ID"] = msgid
    m.set_content(body)
    for name, data in (attach or []):
        m.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    path.write_bytes(bytes(m))


def test_registered():
    assert get("mail") is mail.run


def test_requires_dir():
    with pytest.raises(ValueError):
        mail.run()
    with pytest.raises(ValueError):
        mail.run(dir="/nonexistent-dir-xyz")


def test_clean_dir_no_findings(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    eml(tmp_path / "n.eml", "Newsletter https://example.com/x")
    assert mail.run(dir=str(tmp_path)) == []


def test_dangerous_and_macro_files(tmp_path):
    (tmp_path / "setup.exe").write_bytes(b"MZ" + b"\0" * 20)
    with zipfile.ZipFile(tmp_path / "m.docm", "w") as z:
        z.writestr("[Content_Types].xml", "<x/>")
        z.writestr("word/vbaProject.bin", b"x")
    (tmp_path / "old.doc").write_bytes(bytes.fromhex("D0CF11E0A1B11AE1") + b"\0" * 32)
    fs = mail.run(dir=str(tmp_path))
    klasses = {(os.path.basename(f.location), f.klass) for f in fs}
    assert ("setup.exe", "mail.dangerous-attachment") in klasses
    assert ("m.docm", "mail.macro") in klasses
    assert ("old.doc", "mail.macro") in klasses


def test_av_hit_is_malware(tmp_path, monkeypatch):
    p = tmp_path / "x.txt"
    p.write_text("x")
    monkeypatch.setattr(filescreen, "av_scan_batch", lambda ps: ("clamscan", {str(p): "Sig.A"}))
    fs = mail.run(dir=str(tmp_path))
    assert [f.klass for f in fs] == ["mail.malware"]
    assert fs[0].severity == "critical" and fs[0].location == str(p)


def test_eml_attachment_and_phish_link(tmp_path):
    eml(tmp_path / "p.eml", "click http://bit.ly/secret-token-123 to verify your password now",
        subject="Urgent", attach=[("invoice.pdf.exe", b"MZ" + b"\0" * 10)],
        msgid="<phish@evil.example>")
    fs = mail.run(dir=str(tmp_path))
    klasses = {f.klass for f in fs}
    assert "mail.phish-link" in klasses and "mail.dangerous-attachment" in klasses
    locs = {f.location for f in fs}
    assert "<phish@evil.example>" in locs
    assert "<phish@evil.example>#invoice.pdf.exe" in locs
    blob = json.dumps([f.to_dict() for f in fs])
    assert "secret-token-123" not in blob and "verify your password" not in blob


def test_stable_fingerprints_and_no_modification(tmp_path):
    (tmp_path / "setup.exe").write_bytes(b"MZ" + b"\0" * 20)
    eml(tmp_path / "p.eml", "act now: click http://bit.ly/x to verify", subject="Urgent",
        attach=[("a.exe", b"MZ")])
    before = snapshot(tmp_path)
    a = mail.run(dir=str(tmp_path))
    b = mail.run(dir=str(tmp_path))
    assert [f.fingerprint for f in a] == [f.fingerprint for f in b]
    assert len({f.fingerprint for f in a}) == len(a)
    assert snapshot(tmp_path) == before


def test_cli_sweep_mail(tmp_path):
    (tmp_path / "setup.exe").write_bytes(b"MZ" + b"\0" * 20)
    r = CliRunner().invoke(cli, ["sweep", "mail", "--opt", f"dir={tmp_path}", "--format", "json"])
    assert r.exit_code == 1
    assert json.loads(r.output)["findings"][0]["sweep"] == "mail"
