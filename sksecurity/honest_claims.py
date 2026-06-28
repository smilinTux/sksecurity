"""
SKSecurity Enterprise — Honest Claims Scanner (the no-overclaim gate).

Security marketing rots into lies the moment it promises more than the math
delivers. This module scans docs, code, and comments for forbidden security
overclaims — "quantum-proof", "quantum-safe", "unbreakable", "uncrackable",
"100% secure", and "military-grade" used as a security claim — and exits
non-zero when a *real* claim is found.

It is deliberately tolerant of honest discipline. The whole point of this
ecosystem's crypto standard is that you must SAY the forbidden words in order
to forbid them ("never quantum-proof"), quote them in a policy ("❌
'unbreakable'"), or list them in a test (`_FORBIDDEN = (...)`). Those are
negations / meta-references, not claims, and are allowed.

Honesty discipline this gate encodes (sk-standards CRYPTOGRAPHY_STANDARD):
  * A classical KEM stays harvest-now-decrypt-later (HNDL) exposed forever —
    nothing classical is "quantum-proof".
  * A hybrid scheme is only as strong as its strongest *surviving* leg; it is
    not "unbreakable", it degrades to whichever leg holds.
  * Cite the standard, not the adjective: FIPS 203 (ML-KEM), FIPS 204
    (ML-DSA), FIPS 205 (SLH-DSA).

Pure-Python, zero hard dependencies, regex-driven — same shape as
`secret_guard.py` so it slots straight into the CLI and CI.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ──────────────────────────────────────────────────────────────────────
# Findings + result objects
# ──────────────────────────────────────────────────────────────────────


@dataclass
class ClaimFinding:
    """A single forbidden security overclaim found in text."""

    claim: str            # canonical label, e.g. "quantum-proof"
    severity: str         # CRITICAL | HIGH
    file_path: str
    line_number: int
    matched_text: str     # the exact span that matched
    line_text: str        # the full source line (stripped)
    rationale: str        # why this is a lie / what is actually true
    suggestion: str       # what to say instead

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim": self.claim,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "matched_text": self.matched_text,
            "line_text": self.line_text,
            "rationale": self.rationale,
            "suggestion": self.suggestion,
        }


@dataclass
class ClaimScanResult:
    """Aggregate result of an honest-claims scan."""

    target: str
    findings: List[ClaimFinding] = field(default_factory=list)
    files_scanned: int = 0
    scanned_at: datetime = field(default_factory=datetime.now)

    @property
    def has_violations(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "scanned_at": self.scanned_at.isoformat(),
            "has_violations": self.has_violations,
            "critical_count": self.critical_count,
        }

    def format_report(self) -> str:
        lines = [
            "📏 SKSecurity Honest-Claims Report (no-overclaim gate)",
            "=" * 56,
            f"📁 Target: {self.target}",
            f"📄 Files Scanned: {self.files_scanned}",
            f"📅 Scanned: {self.scanned_at.isoformat()}",
            "",
        ]
        if not self.findings:
            lines.append(
                "✅ No forbidden security overclaims. Claims match the math."
            )
        else:
            lines.append(f"🚨 Found {len(self.findings)} overclaim(s):")
            lines.append("-" * 40)
            for i, f in enumerate(self.findings, 1):
                icon = "🔴" if f.severity == "CRITICAL" else "🟠"
                lines.append(f"  {icon} {f.claim}  ({f.severity})")
                lines.append(f"     File: {f.file_path}:{f.line_number}")
                lines.append(f"     Line: {f.line_text}")
                lines.append(f"     Why:  {f.rationale}")
                lines.append(f"     Say:  {f.suggestion}")
                lines.append("")
            lines.append(
                "Suppress an honest reference with `# honest-claims: allow`, "
                "phrase it as a negation, or add the file to .honestclaims-allow."
            )

        lines.append("🛡️ Powered by SKSecurity Enterprise")
        return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────
# Forbidden claim definitions
# ──────────────────────────────────────────────────────────────────────
# Each entry: (compiled_regex, label, severity, requires_security_context,
#              rationale, suggestion)
# `requires_security_context=True` means the phrase only counts as a
# violation when the surrounding line also mentions security/crypto — so
# "military-grade titanium" is fine but "military-grade encryption" is not.

ClaimPattern = Tuple[re.Pattern, str, str, bool, str, str]

FORBIDDEN_CLAIMS: List[ClaimPattern] = [
    (
        re.compile(r"quantum[\s\-]?proof", re.IGNORECASE),
        "quantum-proof",
        "CRITICAL",
        False,
        "Nothing classical is quantum-proof; a classical KEM stays HNDL-exposed "
        "and a hybrid only holds while one leg survives.",
        'Say "post-quantum" / "quantum-resistant" and cite FIPS 203/204.',
    ),
    (
        re.compile(r"quantum[\s\-]?safe", re.IGNORECASE),
        "quantum-safe",
        "CRITICAL",
        False,
        "\"Quantum-safe\" implies a proven guarantee no scheme can give.",
        'Say "post-quantum" / "quantum-resistant" and name the algorithm.',
    ),
    (
        re.compile(r"unbreakable", re.IGNORECASE),
        "unbreakable",
        "CRITICAL",
        False,
        "No deployed cipher is unbreakable; security is a work factor, not a "
        "guarantee.",
        'State the security level / algorithm (e.g. "AES-256", "ML-KEM-768").',
    ),
    (
        re.compile(r"uncrackable", re.IGNORECASE),
        "uncrackable",
        "CRITICAL",
        False,
        "\"Uncrackable\" is an absolute no real system meets.",
        "Describe the concrete work factor or threat model instead.",
    ),
    (
        re.compile(r"100\s*%\s*secure|100\s+percent\s+secure", re.IGNORECASE),
        "100% secure",
        "CRITICAL",
        False,
        "Nothing is 100% secure; you reduce and bound risk, you do not "
        "eliminate it.",
        'Say "reduces risk" / "defense in depth" with the actual controls.',
    ),
    (
        re.compile(r"military[\s\-]?grade", re.IGNORECASE),
        "military-grade",
        "HIGH",
        True,  # only a violation as a *security* claim
        "\"Military-grade\" is marketing, not a spec — it asserts a pedigree "
        "the math does not.",
        'Name the primitive and parameters (e.g. "AES-256-GCM", "X25519").',
    ),
]

# Words that, when present near a `military-grade` hit, make it a *security*
# claim rather than a materials/quality claim.
_SECURITY_CONTEXT = re.compile(
    r"encrypt|decrypt|crypto|cipher|security|secure|protect|key|aes|rsa|tls|"
    r"ssl|hash|vpn|auth|password|signature|kem",
    re.IGNORECASE,
)

# Tokens that signal the forbidden phrase is being negated / discussed, not
# asserted. Matched as whole words (case-insensitive) within the enclosing
# sentence, plus a few multi-word and symbol markers handled separately.
_NEGATION_WORDS: Set[str] = {
    "never", "not", "no", "none", "nothing", "neither", "nor", "without",
    "avoid", "avoids", "avoiding", "forbid", "forbids", "forbidden",
    "ban", "bans", "banned", "prohibit", "prohibits", "prohibited",
    "cannot", "cant", "dont", "doesnt", "isnt", "arent", "wasnt", "wont",
    "false", "myth", "mythical", "debunk", "debunks", "debunked",
    "instead", "rather", "claim", "claims", "claiming", "imply", "implies",
}
_NEGATION_WORD_RE = re.compile(
    r"\b(" + "|".join(sorted(_NEGATION_WORDS, key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)
# Multi-word / symbol negation markers checked by substring.
_NEGATION_MARKERS: Tuple[str, ...] = (
    "❌", "🚫", "no such thing", "not truly", "n't",
)
# Inline directives that suppress a whole line.
_INLINE_ALLOW = re.compile(r"honest[-\s]?claims:\s*allow|noqa:\s*honest[-\s]?claims",
                           re.IGNORECASE)
# Sentence boundary characters used to scope negation detection.
_SENTENCE_BOUNDARY = ".!?"
_QUOTE_CHARS = "\"'`“”«»"

SKIP_EXTENSIONS: Set[str] = {
    ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin", ".o", ".a", ".class",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".whl",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".woff", ".woff2", ".ttf", ".eot",
    ".lock", ".min.js", ".min.css",
}

SKIP_DIRS: Set[str] = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", ".eggs", "site-packages",
}


# ──────────────────────────────────────────────────────────────────────
# Scanner
# ──────────────────────────────────────────────────────────────────────


class HonestClaimsScanner:
    """Scan paths/text for forbidden security overclaims.

    Args:
        allowlist: list of fnmatch globs / substrings matched against a
            file's path; matching files are skipped entirely.
        allowlist_file: path to a newline-delimited allowlist file (``#``
            comments allowed); merged with ``allowlist``.
    """

    def __init__(
        self,
        allowlist: Optional[List[str]] = None,
        allowlist_file: Optional[Path] = None,
    ):
        self._allow_globs: List[str] = list(allowlist or [])
        if allowlist_file is not None:
            self._allow_globs.extend(self._load_allowlist(Path(allowlist_file)))

    # ── public API ────────────────────────────────────────────────

    def scan_text(self, text: str, source: str = "<input>") -> List[ClaimFinding]:
        """Scan a blob of text. Returns a list of ClaimFinding (possibly empty)."""
        findings: List[ClaimFinding] = []

        for pattern, label, severity, needs_ctx, rationale, suggestion in FORBIDDEN_CLAIMS:
            for match in pattern.finditer(text):
                start = match.start()
                line_start = text.rfind("\n", 0, start) + 1
                line_end = text.find("\n", start)
                if line_end == -1:
                    line_end = len(text)
                line = text[line_start:line_end]

                if _INLINE_ALLOW.search(line):
                    continue
                if needs_ctx and not _SECURITY_CONTEXT.search(line):
                    continue
                if self._is_negated(text, start, match.end()):
                    continue

                line_num = text.count("\n", 0, start) + 1
                findings.append(
                    ClaimFinding(
                        claim=label,
                        severity=severity,
                        file_path=source,
                        line_number=line_num,
                        matched_text=match.group(),
                        line_text=line.strip(),
                        rationale=rationale,
                        suggestion=suggestion,
                    )
                )
        return findings

    def scan_file(self, file_path: Path) -> List[ClaimFinding]:
        """Scan a single file. Returns [] for allowlisted/binary/unreadable files."""
        file_path = Path(file_path)
        if self._is_allowlisted(file_path):
            return []
        if self._has_skip_suffix(file_path):
            return []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            return []
        return self.scan_text(content, source=str(file_path))

    def scan_directory(self, directory: Path) -> ClaimScanResult:
        """Recursively scan a directory tree."""
        directory = Path(directory)
        all_findings: List[ClaimFinding] = []
        files_scanned = 0
        for file_path in self._walkfiles(directory):
            findings = self.scan_file(file_path)
            all_findings.extend(findings)
            files_scanned += 1
        return ClaimScanResult(
            target=str(directory),
            findings=all_findings,
            files_scanned=files_scanned,
        )

    def scan_path(self, path: Path) -> ClaimScanResult:
        """Scan a file or directory, always returning a ClaimScanResult."""
        path = Path(path)
        if path.is_file():
            findings = self.scan_file(path)
            return ClaimScanResult(
                target=str(path), findings=findings, files_scanned=1
            )
        return self.scan_directory(path)

    # ── internals ─────────────────────────────────────────────────

    def _is_negated(self, text: str, start: int, end: int) -> bool:
        """True if the forbidden phrase is a negation / meta reference.

        Strategy: scope to the enclosing sentence (bounded by . ! ? or a blank
        line), then look for negation words anywhere in that sentence — before
        OR after the phrase (handles "Avoid X; never imply that."). Also treat
        a phrase immediately wrapped in quotes as a meta reference.
        """
        # Quoted token => meta reference (e.g. policy lists, test fixtures).
        prev_char = text[start - 1] if start > 0 else ""
        if prev_char and prev_char in _QUOTE_CHARS:
            return True

        sent_start = self._sentence_start(text, start)
        sent_end = self._sentence_end(text, end)
        sentence = text[sent_start:sent_end]

        if _NEGATION_WORD_RE.search(sentence):
            return True
        low = sentence.lower()
        return any(marker in low for marker in _NEGATION_MARKERS)

    @staticmethod
    def _sentence_start(text: str, pos: int) -> int:
        """Index just after the previous sentence boundary or blank line."""
        boundary = 0
        for ch in _SENTENCE_BOUNDARY:
            idx = text.rfind(ch, 0, pos)
            if idx + 1 > boundary:
                boundary = idx + 1
        blank = text.rfind("\n\n", 0, pos)
        if blank != -1 and blank + 2 > boundary:
            boundary = blank + 2
        return boundary

    @staticmethod
    def _sentence_end(text: str, pos: int) -> int:
        """Index of the next sentence boundary or blank line."""
        candidates = []
        for ch in _SENTENCE_BOUNDARY:
            idx = text.find(ch, pos)
            if idx != -1:
                candidates.append(idx + 1)
        blank = text.find("\n\n", pos)
        if blank != -1:
            candidates.append(blank)
        return min(candidates) if candidates else len(text)

    def _is_allowlisted(self, file_path: Path) -> bool:
        if not self._allow_globs:
            return False
        path_str = str(file_path)
        name = file_path.name
        for glob in self._allow_globs:
            if (
                fnmatch.fnmatch(path_str, glob)
                or fnmatch.fnmatch(name, glob)
                or glob in path_str
            ):
                return True
        return False

    @staticmethod
    def _has_skip_suffix(file_path: Path) -> bool:
        suffixes = "".join(file_path.suffixes).lower()
        if file_path.suffix.lower() in SKIP_EXTENSIONS:
            return True
        return any(suffixes.endswith(s) for s in SKIP_EXTENSIONS)

    def _walkfiles(self, directory: Path):
        for root, dirs, files in os.walk(directory):
            dirs[:] = [
                d for d in dirs
                if d not in SKIP_DIRS and not d.endswith(".egg-info")
            ]
            for filename in files:
                file_path = Path(root) / filename
                if not self._has_skip_suffix(file_path):
                    yield file_path

    @staticmethod
    def _load_allowlist(path: Path) -> List[str]:
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return []
        globs: List[str] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            globs.append(line)
        return globs


__all__ = ["HonestClaimsScanner", "ClaimScanResult", "ClaimFinding", "FORBIDDEN_CLAIMS"]
