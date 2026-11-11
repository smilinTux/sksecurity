"""Report-only screening of files (mail attachments and downloads).

Checks, none of which modify, move, delete or extract the file:

- ClamAV (``clamdscan`` when a clamd socket exists, else ``clamscan``; if
  neither is installed the verdict records ``av="unavailable"`` and carries on)
- dangerous and double extensions (reuses ``EmailScreener._check_attachments``)
- magic bytes versus extension (a PE or ELF named ``.pdf``)
- Office macros (OOXML ``vbaProject.bin``, legacy OLE documents)
- zip archives: members are listed, never extracted, and the extension rules
  apply to each member; encrypted members are flagged

Public API: :func:`screen_file`, :func:`screen_files`, :class:`FileVerdict`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .email_screener import EmailScreener, ScreeningFinding, ThreatCategory, Verdict

AV_TIMEOUT_S = 180
MAX_ZIP_MEMBERS = 5000

_CLAMD_SOCKETS = (
    "/run/clamav/clamd.ctl",
    "/var/run/clamav/clamd.ctl",
    "/run/clamav/clamd.sock",
    "/var/lib/clamav/clamd.sock",
    "/tmp/clamd.socket",
)

_EXEC_EXTS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".drv", ".so", ".bin",
    ".elf", ".o", ".dylib", ".out", ".run", ".appimage",
}
_OLE_EXTS = {".doc", ".xls", ".ppt", ".dot", ".xlt", ".pot", ".pps", ".xla", ".ppa"}
_OOXML_MAGIC_MEMBER = "[Content_Types].xml"

_OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")


def _ext(name: str) -> str:
    base = os.path.basename(name)
    return "." + base.rsplit(".", 1)[-1].lower() if "." in base else ""


def _exec_kind(head: bytes) -> Optional[str]:
    if head[:2] == b"MZ":
        return "PE (Windows executable)"
    if head[:4] == b"\x7fELF":
        return "ELF executable"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "Mach-O executable"
    return None


@dataclass
class FileVerdict:
    path: str
    verdict: Verdict
    risk_score: float
    findings: List[ScreeningFinding] = field(default_factory=list)
    av: str = "unavailable"  # clamdscan | clamscan | unavailable
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_malicious(self) -> bool:
        return self.verdict == Verdict.MALICIOUS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "verdict": self.verdict.value,
            "risk_score": round(self.risk_score, 1),
            "av": self.av,
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }


def _clamd_socket_exists() -> bool:
    return any(os.path.exists(s) for s in _CLAMD_SOCKETS)


def av_scan(path: str) -> Tuple[str, Optional[str]]:
    """Scan with ClamAV. Returns (engine, signature_or_None).

    engine is "clamdscan", "clamscan" or "unavailable" (also on scan error).
    """
    candidates: List[Tuple[str, List[str]]] = []
    if shutil.which("clamdscan") and _clamd_socket_exists():
        candidates.append(("clamdscan", ["clamdscan", "--no-summary", "--infected", "--fdpass", "--", path]))
    if shutil.which("clamscan"):
        candidates.append(("clamscan", ["clamscan", "--no-summary", "--infected", "--", path]))
    for engine, cmd in candidates:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=AV_TIMEOUT_S)
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode == 1:
            sig = ""
            for line in proc.stdout.splitlines():
                if line.rstrip().endswith("FOUND"):
                    sig = line.rsplit(":", 1)[-1].replace("FOUND", "").strip()
                    break
            return engine, sig or "unknown signature"
        if proc.returncode == 0:
            return engine, None
        # returncode 2 = scan error: try the next engine
    return "unavailable", None


def _finding(cat: ThreatCategory, sev: str, conf: float, desc: str,
             match: str = "", fix: str = "") -> ScreeningFinding:
    return ScreeningFinding(category=cat, severity=sev, confidence=conf,
                            description=desc, matched_text=match, remediation=fix)


def _check_zip(path: str, screener: EmailScreener) -> List[ScreeningFinding]:
    out: List[ScreeningFinding] = []
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return out
    with zf:
        infos = zf.infolist()[:MAX_ZIP_MEMBERS]
        names = [i.filename for i in infos]
        is_ooxml = _OOXML_MAGIC_MEMBER in names
        if any(os.path.basename(n).lower() == "vbaproject.bin" for n in names):
            out.append(_finding(
                ThreatCategory.MALWARE_PAYLOAD, "HIGH", 0.85,
                "Office document contains VBA macros (vbaProject.bin)",
                os.path.basename(path), "Do not enable macros; open only if the sender is verified."))
        if is_ooxml:
            return out
        if any(i.flag_bits & 0x1 for i in infos):
            out.append(_finding(
                ThreatCategory.MALWARE_PAYLOAD, "MEDIUM", 0.6,
                "Encrypted zip: contents cannot be inspected",
                os.path.basename(path), "Treat as untrusted; encrypted archives evade scanners."))
        for f in screener._check_attachments([n for n in names if not n.endswith("/")]):
            f.description = f"Archive member: {f.description}"
            out.append(f)
    return out


def screen_file(path: str) -> FileVerdict:
    """Screen one file. Read-only: the file is never modified, moved or deleted."""
    screener = EmailScreener()
    findings: List[ScreeningFinding] = []
    meta: Dict[str, Any] = {}
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(8192)
    except OSError as exc:
        findings.append(_finding(ThreatCategory.MALWARE_PAYLOAD, "MEDIUM", 0.6,
                                 f"File could not be read: {type(exc).__name__}", path))
        score = screener._calculate_risk_score(findings)
        return FileVerdict(path, screener._determine_verdict(score, findings), score, findings)
    meta["size"] = size
    base = os.path.basename(path)
    ext = _ext(base)

    engine, sig = av_scan(path)
    if sig is not None:
        findings.append(_finding(
            ThreatCategory.MALWARE_PAYLOAD, "CRITICAL", 0.99,
            f"ClamAV detection: {sig}", base,
            "Do not open. Keep quarantined and delete after review."))
    elif engine == "unavailable":
        meta["note"] = "av unavailable"

    findings.extend(screener._check_attachments([base]))

    kind = _exec_kind(head)
    if kind and ext not in _EXEC_EXTS:
        findings.append(_finding(
            ThreatCategory.MALWARE_PAYLOAD, "CRITICAL", 0.9,
            f"Content is a {kind} but the name says {ext or 'no extension'}", base,
            "Executable disguised as another file type."))

    if head[:8] == _OLE_MAGIC and ext in _OLE_EXTS:
        findings.append(_finding(
            ThreatCategory.MALWARE_PAYLOAD, "MEDIUM", 0.6,
            "Legacy Office (OLE) document may contain macros", base,
            "Open in Protected View or convert before opening."))

    if head[:4] == b"PK\x03\x04":
        findings.extend(_check_zip(path, screener))

    score = screener._calculate_risk_score(findings)
    return FileVerdict(path, screener._determine_verdict(score, findings),
                       score, findings, av=engine, metadata=meta)


def expand_paths(paths: Iterable[str]) -> List[str]:
    """Files as given; directories are walked (symlinks not followed)."""
    out: List[str] = []
    for p in paths:
        if os.path.isdir(p) and not os.path.islink(p):
            for root, _dirs, files in os.walk(p):
                out.extend(os.path.join(root, f) for f in sorted(files))
        else:
            out.append(p)
    return out


def screen_files(paths: Iterable[str]) -> List[FileVerdict]:
    return [screen_file(p) for p in expand_paths(paths)]
