"""Mail sweep: screen a directory of already-downloaded messages and attachments.

Usage: ``sksecurity sweep mail --opt dir=PATH``

Files in ``dir`` are screened with :mod:`sksecurity.filescreen`. ``.eml``
messages are parsed: links and phishing language are screened with
``EmailScreener`` and each attachment is screened as a file (written to a
private temp dir that is removed afterwards). This sweep never talks to Gmail
and never modifies, moves or deletes anything in ``dir``. Findings carry a
file path or message id as location and never include message bodies or URLs.
"""

from __future__ import annotations

import email
import hashlib
import os
import re
import tempfile
from email import policy
from typing import Dict, List, Tuple

from ..email_screener import EmailScreener, ScreeningFinding, ThreatCategory, Verdict
from ..filescreen import expand_paths, screen_files
from ..findings import Finding, make_fingerprint

NAME = "mail"
HELP = "Screen downloaded mail attachments and .eml messages (dir=PATH)."

MAX_ATTACHMENT_BYTES = 50 * 1024 * 1024
_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _klass(f: ScreeningFinding) -> str:
    d = f.description.lower()
    if d.startswith("clamav detection"):
        return "mail.malware"
    if "macro" in d:
        return "mail.macro"
    return "mail.dangerous-attachment"


def _file_sha(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return "unreadable"
    return h.hexdigest()[:16]


def _mk(klass: str, f: ScreeningFinding, location: str, ident: str, **details) -> Finding:
    rule = re.sub(r"\s+", "-", f.description.lower())[:60]
    return Finding(
        sweep=NAME,
        klass=klass,
        severity=_SEV.get(f.severity, "medium"),
        location=location,
        summary=f.description,
        fingerprint=make_fingerprint(NAME, klass, location, rule, ident),
        rule=rule,
        remediation=f.remediation,
        details={"category": f.category.value, **details},
    )


def _html_to_text(s: str) -> str:
    return re.sub(r"<[^>]+>", " ", s)


def _body_text(msg) -> str:
    parts: List[str] = []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            text = part.get_content()
        except Exception:
            continue
        parts.append(_html_to_text(text) if ctype == "text/html" else text)
        if ctype == "text/html":
            # keep hrefs: link screening needs them
            parts.append(" ".join(re.findall(r'href=["\']([^"\']+)', text)))
    return "\n".join(parts)


def run(dir: str = "", **_options) -> List[Finding]:  # noqa: A002 (option name is "dir")
    if not dir or not os.path.isdir(dir):
        raise ValueError("mail sweep needs --opt dir=PATH (an existing directory)")
    findings: List[Finding] = []
    screener = EmailScreener()
    files = expand_paths([dir])
    plain = [p for p in files if not p.lower().endswith(".eml")]
    emls = [p for p in files if p.lower().endswith(".eml")]

    # target path -> (location, identity) for files we screen
    targets: Dict[str, Tuple[str, str]] = {p: (p, _file_sha(p)) for p in plain}

    with tempfile.TemporaryDirectory(prefix="sksecurity-mail-") as tmp:
        n = 0
        for eml in emls:
            try:
                with open(eml, "rb") as fh:
                    msg = email.message_from_binary_file(fh, policy=policy.default)
            except Exception:
                continue
            msgid = (msg.get("Message-ID") or "").strip() or os.path.basename(eml)
            names: List[str] = []
            for part in msg.walk():
                fname = part.get_filename()
                if not fname:
                    continue
                base = os.path.basename(fname.replace("\\", "/")) or "attachment"
                names.append(base)
                try:
                    payload = part.get_payload(decode=True) or b""
                except Exception:
                    continue
                if len(payload) > MAX_ATTACHMENT_BYTES:
                    continue
                n += 1
                d = os.path.join(tmp, str(n))
                os.makedirs(d)
                out = os.path.join(d, base)
                with open(out, "wb") as fh:
                    fh.write(payload)
                targets[out] = (f"{msgid}#{base}", hashlib.sha256(payload).hexdigest()[:16])

            sub = str(msg.get("Subject") or "")
            res = screener.screen(_body_text(msg), sender=str(msg.get("From") or "") or None,
                                  subject=sub or None)
            if res.verdict != Verdict.SAFE:
                for f in res.findings:
                    if f.category in (ThreatCategory.MALICIOUS_LINK, ThreatCategory.PHISHING):
                        findings.append(_mk("mail.phish-link", f, msgid, "msg", line=f.line_number))

        verdicts = screen_files(list(targets))
        for v in verdicts:
            location, ident = targets[v.path]
            for f in v.findings:
                findings.append(_mk(_klass(f), f, location, ident, av=v.av))
    seen = set()
    unique = []
    for f in findings:
        if f.fingerprint not in seen:
            seen.add(f.fingerprint)
            unique.append(f)
    return unique
