"""
SKSecurity Enterprise - Secret Leak Prevention Module

Real-time detection of credentials, API keys, private keys, and secrets
in files, git diffs, and agent output. Generates pre-commit hooks and
provides a watcher for continuous protection.

This is the module that would have caught Chef sharing his npm token
in a chat window. Now it protects everyone.
"""

import os
import re
import json
import hashlib
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple


@dataclass
class SecretFinding:
    """A detected secret or credential."""
    secret_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM
    file_path: str
    line_number: int
    matched_text: str
    redacted_text: str
    confidence: float
    description: str
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "secret_type": self.secret_type,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "redacted_text": self.redacted_text,
            "confidence": self.confidence,
            "description": self.description,
            "remediation": self.remediation,
        }


@dataclass
class GuardResult:
    """Result of a secret guard scan."""
    target: str
    findings: List[SecretFinding] = field(default_factory=list)
    files_scanned: int = 0
    scanned_at: datetime = field(default_factory=datetime.now)

    @property
    def has_secrets(self) -> bool:
        """Check if any secrets were found."""
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        """Count of CRITICAL findings."""
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "scanned_at": self.scanned_at.isoformat(),
            "has_secrets": self.has_secrets,
            "critical_count": self.critical_count,
        }

    def format_report(self) -> str:
        """Format as human-readable report."""
        lines = [
            "🔐 SKSecurity Secret Guard Report",
            "=" * 50,
            f"📁 Target: {self.target}",
            f"📄 Files Scanned: {self.files_scanned}",
            f"📅 Scanned: {self.scanned_at.isoformat()}",
            "",
        ]
        if not self.findings:
            lines.append("✅ No secrets or credentials detected. You're clean!")
        else:
            lines.append(f"🚨 Found {len(self.findings)} secret(s):")
            lines.append("-" * 30)
            for i, finding in enumerate(self.findings, 1):
                icon = "🔴" if finding.severity == "CRITICAL" else "🟠"
                lines.append(f"  {icon} {finding.secret_type}")
                lines.append(f"     File: {finding.file_path}:{finding.line_number}")
                lines.append(f"     Match: {finding.redacted_text}")
                lines.append(f"     {finding.description}")
                if finding.remediation:
                    lines.append(f"     Fix: {finding.remediation}")
                lines.append("")

        lines.append("🛡️ Powered by SKSecurity Enterprise")
        return "\n".join(lines)


# Reason: each tuple is (compiled_regex, type_name, severity, confidence, description)
SECRET_PATTERNS: List[Tuple[re.Pattern, str, str, float, str]] = [
    (
        re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
        "AWS Access Key",
        "CRITICAL",
        0.95,
        "AWS IAM access key detected",
    ),
    (
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"),
        "GitHub Token",
        "CRITICAL",
        0.95,
        "GitHub personal/OAuth/app token detected",
    ),
    (
        re.compile(r"npm_[A-Za-z0-9]{36,}"),
        "npm Token",
        "CRITICAL",
        0.95,
        "npm access token detected",
    ),
    (
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
        "OpenAI API Key",
        "CRITICAL",
        0.90,
        "OpenAI-style API key detected",
    ),
    (
        re.compile(r"xox[bpras]-[A-Za-z0-9\-]{10,}"),
        "Slack Token",
        "CRITICAL",
        0.93,
        "Slack bot/user/app token detected",
    ),
    (
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "Private Key",
        "CRITICAL",
        0.99,
        "Private key file or embedded private key",
    ),
    (
        re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        "SendGrid API Key",
        "CRITICAL",
        0.95,
        "SendGrid API key detected",
    ),
    (
        re.compile(r"(?:sq0atp|sq0csp)-[A-Za-z0-9_-]{22,}"),
        "Square Token",
        "CRITICAL",
        0.90,
        "Square access/OAuth token detected",
    ),
    (
        re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{24,}"),
        "Stripe Secret Key",
        "CRITICAL",
        0.95,
        "Stripe secret key detected",
    ),
    (
        re.compile(r"(?:mongodb(?:\+srv)?://)[^\s]+:[^\s]+@[^\s]+"),
        "MongoDB Connection String",
        "HIGH",
        0.85,
        "MongoDB connection string with credentials",
    ),
    (
        re.compile(r"postgres(?:ql)?://[^\s]+:[^\s]+@[^\s]+"),
        "PostgreSQL Connection String",
        "HIGH",
        0.85,
        "PostgreSQL connection string with credentials",
    ),
    (
        re.compile(
            r"(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|auth)"
            r"\s*[:=]\s*['\"][^'\"]{8,}['\"]",
            re.IGNORECASE,
        ),
        "Hardcoded Credential",
        "HIGH",
        0.75,
        "Hardcoded credential assignment detected",
    ),
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
        "JWT Token",
        "HIGH",
        0.85,
        "JSON Web Token detected (may contain sensitive claims)",
    ),
]

SKIP_EXTENSIONS: Set[str] = {
    ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".woff", ".woff2", ".ttf", ".eot",
    ".lock",
}

SKIP_DIRS: Set[str] = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".eggs", "*.egg-info",
}


class SecretGuard:
    """
    Detects secrets and credentials in files, git staging areas,
    and arbitrary text. Generates pre-commit hooks for CI integration.
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the secret guard.

        Args:
            config: Optional configuration dict.
        """
        self.config = config or {}
        self._allow_patterns: List[str] = self.config.get(
            "secret_guard.allow_patterns", []
        )
        self._extra_patterns: List[Tuple[re.Pattern, str, str, float, str]] = []

    def scan_text(self, text: str, source: str = "<input>") -> List[SecretFinding]:
        """
        Scan arbitrary text for secrets.

        Args:
            text: The text content to scan.
            source: Label for the source of the text.

        Returns:
            List of SecretFinding objects.
        """
        findings: List[SecretFinding] = []
        all_patterns = SECRET_PATTERNS + self._extra_patterns

        for pattern, secret_type, severity, confidence, description in all_patterns:
            for match in pattern.finditer(text):
                matched = match.group()
                if self._is_allowed(matched):
                    continue
                if self._is_test_context(text, match.start()):
                    continue

                line_num = text[: match.start()].count("\n") + 1
                findings.append(
                    SecretFinding(
                        secret_type=secret_type,
                        severity=severity,
                        file_path=source,
                        line_number=line_num,
                        matched_text=matched,
                        redacted_text=self._redact(matched),
                        confidence=confidence,
                        description=description,
                        remediation=self._remediation_for(secret_type),
                    )
                )
        return findings

    def scan_file(self, file_path: Path) -> List[SecretFinding]:
        """
        Scan a single file for secrets.

        Args:
            file_path: Path to the file.

        Returns:
            List of SecretFinding objects.
        """
        if file_path.suffix.lower() in SKIP_EXTENSIONS:
            return []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            return []

        return self.scan_text(content, source=str(file_path))

    def scan_directory(self, directory: Path) -> GuardResult:
        """
        Recursively scan a directory for secrets.

        Args:
            directory: Root directory to scan.

        Returns:
            GuardResult with all findings.
        """
        all_findings: List[SecretFinding] = []
        files_scanned = 0

        for file_path in self._walkfiles(directory):
            findings = self.scan_file(file_path)
            all_findings.extend(findings)
            files_scanned += 1

        return GuardResult(
            target=str(directory),
            findings=all_findings,
            files_scanned=files_scanned,
        )

    def scan_git_staged(self, repo_path: Optional[Path] = None) -> GuardResult:
        """
        Scan only git-staged files (what would be committed).
        This is what the pre-commit hook calls.

        Args:
            repo_path: Path to the git repository root.

        Returns:
            GuardResult with findings from staged files.
        """
        repo = repo_path or Path.cwd()
        try:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                capture_output=True,
                text=True,
                cwd=str(repo),
            )
            if result.returncode != 0:
                return GuardResult(target=str(repo))

            staged_files = [
                repo / f.strip()
                for f in result.stdout.strip().split("\n")
                if f.strip()
            ]
        except FileNotFoundError:
            return GuardResult(target=str(repo))

        all_findings: List[SecretFinding] = []
        files_scanned = 0

        for file_path in staged_files:
            if file_path.suffix.lower() not in SKIP_EXTENSIONS and file_path.exists():
                findings = self.scan_file(file_path)
                all_findings.extend(findings)
                files_scanned += 1

        return GuardResult(
            target=f"git staged ({repo})",
            findings=all_findings,
            files_scanned=files_scanned,
        )

    def install_pre_commit_hook(self, repo_path: Optional[Path] = None) -> Path:
        """
        Install a git pre-commit hook that blocks commits containing secrets.

        Args:
            repo_path: Path to the git repository root.

        Returns:
            Path to the installed hook file.
        """
        repo = repo_path or Path.cwd()
        hooks_dir = repo / ".git" / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        hook_path = hooks_dir / "pre-commit"

        hook_script = self._generate_hook_script()

        existing_content = ""
        if hook_path.exists():
            existing_content = hook_path.read_text()
            if "sksecurity-secret-guard" in existing_content:
                return hook_path

        if existing_content and not existing_content.strip().endswith(
            "# END sksecurity-secret-guard"
        ):
            # Reason: append to existing hook rather than overwriting
            with open(hook_path, "a") as f:
                f.write("\n" + hook_script)
        else:
            hook_path.write_text(hook_script)

        hook_path.chmod(0o755)
        return hook_path

    def _generate_hook_script(self) -> str:
        """Generate the pre-commit hook shell script."""
        return """#!/usr/bin/env bash
# sksecurity-secret-guard pre-commit hook
# Blocks commits that contain secrets, API keys, or credentials.
# Installed by: sksecurity guard install

set -e

echo "🔐 SKSecurity: Scanning staged files for secrets..."

if command -v python3 &>/dev/null; then
    PYTHON=python3
elif command -v python &>/dev/null; then
    PYTHON=python
else
    echo "⚠️  SKSecurity: Python not found, skipping secret scan"
    exit 0
fi

RESULT=$($PYTHON -c "
import sys
try:
    from sksecurity.secret_guard import SecretGuard
    guard = SecretGuard()
    result = guard.scan_git_staged()
    if result.has_secrets:
        print(result.format_report())
        sys.exit(1)
    else:
        print('✅ No secrets detected. Commit approved.')
        sys.exit(0)
except ImportError:
    print('⚠️  sksecurity not installed, skipping secret scan')
    sys.exit(0)
except Exception as e:
    print(f'⚠️  Secret scan error: {e}')
    sys.exit(0)
" 2>&1)

EXIT_CODE=$?
echo "$RESULT"

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "🚫 Commit BLOCKED by SKSecurity Secret Guard"
    echo "   Remove the detected secrets and try again."
    echo "   To bypass (NOT recommended): git commit --no-verify"
    exit 1
fi

# END sksecurity-secret-guard
"""

    def _walkfiles(self, directory: Path):
        """
        Walk directory yielding scannable files, respecting skip lists.

        Args:
            directory: Root directory.

        Yields:
            Path objects for each scannable file.
        """
        for root, dirs, files in os.walk(directory):
            dirs[:] = [
                d for d in dirs
                if d not in SKIP_DIRS and not d.endswith(".egg-info")
            ]
            for filename in files:
                file_path = Path(root) / filename
                if file_path.suffix.lower() not in SKIP_EXTENSIONS:
                    yield file_path

    def _is_allowed(self, matched_text: str) -> bool:
        """Check if the matched text is in the allow list."""
        for pattern in self._allow_patterns:
            if re.search(pattern, matched_text):
                return True
        return False

    def _is_test_context(self, content: str, match_pos: int) -> bool:
        """
        Check if the match is inside a test/example/doc context.

        Args:
            content: Full text content.
            match_pos: Position of the match start.

        Returns:
            True if match appears to be in documentation/test context.
        """
        line_start = content.rfind("\n", 0, match_pos) + 1
        line_end = content.find("\n", match_pos)
        if line_end == -1:
            line_end = len(content)
        line = content[line_start:line_end]

        test_indicators = [
            "example", "test", "sample", "demo", "fake", "dummy",
            "placeholder", "your_", "xxx", "changeme",
        ]
        line_lower = line.lower()
        return any(indicator in line_lower for indicator in test_indicators)

    @staticmethod
    def _redact(text: str) -> str:
        """Redact a secret, showing only first/last 4 characters."""
        if len(text) <= 10:
            return "***REDACTED***"
        return f"{text[:4]}{'*' * min(len(text) - 8, 20)}{text[-4:]}"

    @staticmethod
    def _remediation_for(secret_type: str) -> str:
        """Return remediation guidance for a given secret type."""
        remediations = {
            "AWS Access Key": "Rotate the key in AWS IAM Console immediately. Use environment variables or AWS Secrets Manager.",
            "GitHub Token": "Revoke at github.com/settings/tokens and generate a new one with minimal scope.",
            "npm Token": "Revoke at npmjs.com/settings/tokens. Create a new granular access token.",
            "OpenAI API Key": "Regenerate at platform.openai.com/api-keys. Use environment variables.",
            "Slack Token": "Regenerate in your Slack App settings. Never embed in source code.",
            "Private Key": "Generate a new key pair. This private key is compromised.",
            "SendGrid API Key": "Revoke in SendGrid dashboard. Create a key with minimal permissions.",
            "Stripe Secret Key": "Roll key in Stripe Dashboard. Use restricted keys for specific operations.",
            "MongoDB Connection String": "Change the database password. Use environment variables for connection strings.",
            "PostgreSQL Connection String": "Change the database password. Use environment variables.",
            "Hardcoded Credential": "Move to environment variables or a secret manager (Vault, AWS SSM, etc.).",
            "JWT Token": "JWTs may contain sensitive claims. Ensure they're not logged or stored in code.",
        }
        return remediations.get(
            secret_type,
            "Remove the secret from source code. Use environment variables or a secret manager."
        )
