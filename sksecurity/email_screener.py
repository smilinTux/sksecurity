"""
SKSecurity Enterprise - Email & Input Screening Module

Scans emails, messages, and agent inputs *before* they reach the AI model.
Catches phishing, prompt injection, malicious links, and credential leaks.
"""

import re
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse


class Verdict(str, Enum):
    """Screening verdict for a piece of content."""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    QUARANTINED = "quarantined"


class ThreatCategory(str, Enum):
    """Categories of threats detected in screened content."""
    PHISHING = "phishing"
    PROMPT_INJECTION = "prompt_injection"
    CREDENTIAL_LEAK = "credential_leak"
    MALICIOUS_LINK = "malicious_link"
    SOCIAL_ENGINEERING = "social_engineering"
    MALWARE_PAYLOAD = "malware_payload"
    DATA_EXFILTRATION = "data_exfiltration"


@dataclass
class ScreeningFinding:
    """A single threat finding from screening."""
    category: ThreatCategory
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float
    description: str
    matched_text: str = ""
    line_number: int = 0
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "category": self.category.value,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "matched_text": self.matched_text[:200],
            "line_number": self.line_number,
            "remediation": self.remediation,
        }


@dataclass
class ScreeningResult:
    """Result of screening a piece of content."""
    content_hash: str
    verdict: Verdict
    risk_score: float
    findings: List[ScreeningFinding] = field(default_factory=list)
    screened_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_safe(self) -> bool:
        """Quick check if content passed screening."""
        return self.verdict == Verdict.SAFE

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "content_hash": self.content_hash,
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "findings": [f.to_dict() for f in self.findings],
            "screened_at": self.screened_at.isoformat(),
            "metadata": self.metadata,
        }

    def format_report(self) -> str:
        """Format as human-readable report."""
        lines = [
            "🛡️ SKSecurity Email/Input Screening Report",
            "=" * 50,
            f"📅 Screened: {self.screened_at.isoformat()}",
            f"📊 Risk Score: {self.risk_score:.1f}/100",
            f"🎯 Verdict: {self.verdict.value.upper()}",
            "",
        ]
        if not self.findings:
            lines.append("✅ No threats detected — content is clean.")
        else:
            lines.append(f"🚨 Found {len(self.findings)} issue(s):")
            lines.append("-" * 30)
            for i, finding in enumerate(self.findings, 1):
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
                    finding.severity, "⚪"
                )
                lines.append(f"  {icon} [{finding.severity}] {finding.category.value}")
                lines.append(f"     {finding.description}")
                if finding.matched_text:
                    preview = finding.matched_text[:80].replace("\n", "\\n")
                    lines.append(f"     Match: \"{preview}\"")
                if finding.remediation:
                    lines.append(f"     Fix: {finding.remediation}")
                lines.append("")
        lines.append("🛡️ Powered by SKSecurity Enterprise")
        return "\n".join(lines)


class EmailScreener:
    """
    Screens emails, messages, and arbitrary text input before
    it reaches the AI model.

    Designed to sit as middleware in the OpenClaw agent pipeline:
        raw_input -> EmailScreener.screen() -> if safe -> model
    """

    # Severity weights for risk score calculation
    SEVERITY_WEIGHTS = {
        "CRITICAL": 30.0,
        "HIGH": 18.0,
        "MEDIUM": 8.0,
        "LOW": 3.0,
    }

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the email screener.

        Args:
            config: Optional configuration dict.
        """
        self.config = config or {}
        self._allow_list: List[str] = self.config.get("email_screener.allow_list", [])
        self._block_list: List[str] = self.config.get("email_screener.block_list", [])
        self._max_content_length: int = self.config.get(
            "email_screener.max_content_length", 500_000
        )

    def screen(
        self,
        content: str,
        sender: Optional[str] = None,
        subject: Optional[str] = None,
        attachments: Optional[List[str]] = None,
    ) -> ScreeningResult:
        """
        Screen content for threats before it reaches the AI model.

        Args:
            content: The raw text content (email body, message, agent input).
            sender: Optional sender address for email-specific checks.
            subject: Optional subject line for email-specific checks.
            attachments: Optional list of attachment filenames.

        Returns:
            ScreeningResult with verdict, risk score, and findings.
        """
        content_hash = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:16]

        if len(content) > self._max_content_length:
            return ScreeningResult(
                content_hash=content_hash,
                verdict=Verdict.SUSPICIOUS,
                risk_score=40.0,
                findings=[
                    ScreeningFinding(
                        category=ThreatCategory.DATA_EXFILTRATION,
                        severity="MEDIUM",
                        confidence=0.6,
                        description=f"Content exceeds maximum length ({len(content):,} chars)",
                        remediation="Truncate or split the content before processing.",
                    )
                ],
                metadata={"sender": sender, "subject": subject},
            )

        findings: List[ScreeningFinding] = []

        if sender and self._is_blocked_sender(sender):
            findings.append(
                ScreeningFinding(
                    category=ThreatCategory.PHISHING,
                    severity="HIGH",
                    confidence=0.95,
                    description=f"Sender '{sender}' is on the block list",
                    matched_text=sender,
                    remediation="Do not process content from blocked senders.",
                )
            )

        findings.extend(self._check_prompt_injection(content))
        findings.extend(self._check_credential_leaks(content))
        findings.extend(self._check_malicious_links(content))
        findings.extend(self._check_phishing_patterns(content, sender, subject))
        findings.extend(self._check_social_engineering(content))

        if attachments:
            findings.extend(self._check_attachments(attachments))

        risk_score = self._calculate_risk_score(findings)
        verdict = self._determine_verdict(risk_score, findings)

        return ScreeningResult(
            content_hash=content_hash,
            verdict=verdict,
            risk_score=risk_score,
            findings=findings,
            metadata={
                "sender": sender,
                "subject": subject,
                "content_length": len(content),
                "attachment_count": len(attachments) if attachments else 0,
            },
        )

    def screen_batch(
        self, items: List[Dict[str, Any]]
    ) -> List[ScreeningResult]:
        """
        Screen multiple items at once.

        Args:
            items: List of dicts with keys: content, sender, subject, attachments.

        Returns:
            List of ScreeningResult objects.
        """
        return [
            self.screen(
                content=item.get("content", ""),
                sender=item.get("sender"),
                subject=item.get("subject"),
                attachments=item.get("attachments"),
            )
            for item in items
        ]

    def _is_blocked_sender(self, sender: str) -> bool:
        """Check if sender is on the block list."""
        sender_lower = sender.lower()
        for blocked in self._block_list:
            if blocked.lower() in sender_lower:
                return True
        return False

    def _check_prompt_injection(self, content: str) -> List[ScreeningFinding]:
        """
        Detect prompt injection attempts in content.

        Prompt injection is *the* core threat for AI agents -- an attacker
        embeds instructions in an email/message to hijack the model.
        """
        findings: List[ScreeningFinding] = []
        patterns = [
            (
                r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?|context)",
                "Classic prompt injection: instructs AI to ignore prior context",
                "CRITICAL",
                0.92,
            ),
            (
                r"you\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\s+\w+",
                "Role reassignment injection: attempts to change the AI's identity",
                "HIGH",
                0.80,
            ),
            (
                r"(?:system|admin|root)\s*(?:prompt|instruction|override|command)\s*:",
                "System prompt override attempt",
                "CRITICAL",
                0.90,
            ),
            (
                r"\[(?:SYSTEM|INST|ADMIN)\]",
                "Fake system tag injection",
                "HIGH",
                0.85,
            ),
            (
                r"<\|(?:im_start|im_end|endoftext|system)\|>",
                "Chat template delimiter injection (OpenAI/HF format)",
                "CRITICAL",
                0.95,
            ),
            (
                r"(?:BEGIN|START)\s+(?:NEW\s+)?(?:INSTRUCTION|CONVERSATION|SESSION)",
                "Session boundary injection",
                "HIGH",
                0.80,
            ),
            (
                r"(?:do\s+not|don'?t)\s+(?:tell|inform|alert|warn|notify)\s+(?:the\s+)?(?:user|human|operator)",
                "Stealth instruction: tells AI to hide actions from the user",
                "CRITICAL",
                0.93,
            ),
            (
                r"(?:output|print|return|echo|say)\s+(?:only|just|exactly)\s+['\"]",
                "Output override: forces specific AI output",
                "HIGH",
                0.78,
            ),
        ]

        for pattern, description, severity, confidence in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[: match.start()].count("\n") + 1
                findings.append(
                    ScreeningFinding(
                        category=ThreatCategory.PROMPT_INJECTION,
                        severity=severity,
                        confidence=confidence,
                        description=description,
                        matched_text=match.group(),
                        line_number=line_num,
                        remediation="Strip or sanitize this content before sending to the AI model.",
                    )
                )
        return findings

    def _check_credential_leaks(self, content: str) -> List[ScreeningFinding]:
        """Detect credentials, API keys, and secrets in content."""
        findings: List[ScreeningFinding] = []
        patterns = [
            (r"(?:AKIA|ASIA)[A-Z0-9]{16}", "AWS Access Key ID", "CRITICAL", 0.95),
            (r"ghp_[A-Za-z0-9_]{36,}", "GitHub Personal Access Token", "CRITICAL", 0.95),
            (r"gho_[A-Za-z0-9_]{36,}", "GitHub OAuth Token", "CRITICAL", 0.95),
            (r"npm_[A-Za-z0-9]{36,}", "npm Access Token", "CRITICAL", 0.95),
            (r"sk-[A-Za-z0-9]{20,}", "OpenAI-style API Key", "CRITICAL", 0.90),
            (r"xox[bpras]-[A-Za-z0-9\-]{10,}", "Slack Token", "CRITICAL", 0.93),
            (
                r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
                "Private Key",
                "CRITICAL",
                0.99,
            ),
            (
                r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
                "Hardcoded password",
                "HIGH",
                0.80,
            ),
            (
                r"(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"][^'\"]{16,}['\"]",
                "Hardcoded API/secret key",
                "HIGH",
                0.82,
            ),
            (
                r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
                "JSON Web Token (JWT)",
                "HIGH",
                0.85,
            ),
        ]

        for pattern, description, severity, confidence in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE if "password" in pattern.lower() else 0):
                line_num = content[: match.start()].count("\n") + 1
                findings.append(
                    ScreeningFinding(
                        category=ThreatCategory.CREDENTIAL_LEAK,
                        severity=severity,
                        confidence=confidence,
                        description=f"Detected {description}",
                        matched_text=self._redact(match.group()),
                        line_number=line_num,
                        remediation="Remove the credential and rotate it immediately.",
                    )
                )
        return findings

    def _check_malicious_links(self, content: str) -> List[ScreeningFinding]:
        """Detect suspicious or malicious URLs."""
        findings: List[ScreeningFinding] = []
        url_pattern = re.compile(
            r"https?://[^\s<>\"')\]]+", re.IGNORECASE
        )

        suspicious_tlds = {
            ".tk", ".ml", ".ga", ".cf", ".gq",
            ".top", ".xyz", ".buzz", ".click", ".loan",
        }
        suspicious_keywords = {
            "login", "signin", "verify", "secure", "account",
            "update", "confirm", "banking", "paypal", "wallet",
        }

        for match in url_pattern.finditer(content):
            url = match.group()
            try:
                parsed = urlparse(url)
                hostname = parsed.hostname or ""
            except Exception:
                continue

            risk_signals: List[str] = []

            for tld in suspicious_tlds:
                if hostname.endswith(tld):
                    risk_signals.append(f"suspicious TLD ({tld})")
                    break

            for kw in suspicious_keywords:
                if kw in hostname.lower():
                    risk_signals.append(f"phishing keyword in domain ({kw})")
                    break

            # Reason: IP-based URLs are almost never legitimate in emails
            if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", hostname):
                risk_signals.append("IP address used instead of domain")

            if len(hostname) > 50:
                risk_signals.append("unusually long hostname")

            if "@" in url:
                risk_signals.append("URL contains @ (credential-stuffing pattern)")

            if risk_signals:
                line_num = content[: match.start()].count("\n") + 1
                severity = "HIGH" if len(risk_signals) >= 2 else "MEDIUM"
                findings.append(
                    ScreeningFinding(
                        category=ThreatCategory.MALICIOUS_LINK,
                        severity=severity,
                        confidence=min(0.5 + 0.15 * len(risk_signals), 0.95),
                        description=f"Suspicious URL: {', '.join(risk_signals)}",
                        matched_text=url[:120],
                        line_number=line_num,
                        remediation="Do not follow this link. Verify with the sender through a trusted channel.",
                    )
                )
        return findings

    def _check_phishing_patterns(
        self, content: str, sender: Optional[str], subject: Optional[str]
    ) -> List[ScreeningFinding]:
        """Detect common phishing language patterns."""
        findings: List[ScreeningFinding] = []
        urgency_patterns = [
            (
                r"(?:your\s+account\s+(?:has\s+been|will\s+be)\s+(?:suspended|closed|locked|disabled))",
                "Account threat urgency pattern",
            ),
            (
                r"(?:act\s+(?:now|immediately)|urgent(?:ly)?|time[- ]sensitive|expires?\s+(?:today|soon|in\s+\d+\s+hours?))",
                "Artificial urgency language",
            ),
            (
                r"(?:click\s+(?:here|the\s+link|below)\s+to\s+(?:verify|confirm|update|secure))",
                "Action-required phishing pattern",
            ),
            (
                r"(?:we\s+(?:detected|noticed)\s+(?:suspicious|unusual|unauthorized)\s+(?:activity|access|login))",
                "Suspicious activity scare tactic",
            ),
        ]

        for pattern, description in urgency_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[: match.start()].count("\n") + 1
                findings.append(
                    ScreeningFinding(
                        category=ThreatCategory.PHISHING,
                        severity="MEDIUM",
                        confidence=0.70,
                        description=description,
                        matched_text=match.group(),
                        line_number=line_num,
                        remediation="Verify this message through an independent channel before acting.",
                    )
                )

        if sender and subject:
            # Reason: mismatch between display name domain and sender domain is a classic spoof
            sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
            spoof_keywords = ["support", "admin", "security", "billing", "noreply"]
            if sender_domain and any(kw in sender.lower() for kw in spoof_keywords):
                well_known = {
                    "google.com", "microsoft.com", "apple.com", "amazon.com",
                    "paypal.com", "github.com", "gitlab.com",
                }
                if sender_domain not in well_known and any(
                    brand in sender.lower()
                    for brand in ["google", "microsoft", "apple", "amazon", "paypal"]
                ):
                    findings.append(
                        ScreeningFinding(
                            category=ThreatCategory.PHISHING,
                            severity="HIGH",
                            confidence=0.80,
                            description=f"Sender domain mismatch: claims brand affiliation but sent from {sender_domain}",
                            matched_text=sender,
                            remediation="Do not trust emails that claim to be from a brand but use a different domain.",
                        )
                    )
        return findings

    def _check_social_engineering(self, content: str) -> List[ScreeningFinding]:
        """Detect social engineering tactics targeting AI agents."""
        findings: List[ScreeningFinding] = []
        patterns = [
            (
                r"(?:pretend|act\s+as\s+if|imagine)\s+you\s+(?:are|have|can|were)",
                "Role-play manipulation targeting AI agent",
                "MEDIUM",
                0.65,
            ),
            (
                r"(?:this\s+is\s+a\s+test|testing\s+mode|debug\s+mode|maintenance\s+mode)",
                "False context framing (test/debug mode claim)",
                "MEDIUM",
                0.60,
            ),
            (
                r"(?:admin|administrator|developer|owner)\s+(?:here|speaking|authorized)",
                "False authority claim",
                "HIGH",
                0.75,
            ),
            (
                r"(?:send|forward|share|transfer)\s+(?:all|the|your)\s+(?:data|files?|information|credentials?|keys?|tokens?)",
                "Data exfiltration instruction",
                "CRITICAL",
                0.88,
            ),
        ]

        for pattern, description, severity, confidence in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[: match.start()].count("\n") + 1
                findings.append(
                    ScreeningFinding(
                        category=ThreatCategory.SOCIAL_ENGINEERING,
                        severity=severity,
                        confidence=confidence,
                        description=description,
                        matched_text=match.group(),
                        line_number=line_num,
                        remediation="Reject social engineering attempts. Verify through trusted channels.",
                    )
                )
        return findings

    def _check_attachments(self, filenames: List[str]) -> List[ScreeningFinding]:
        """Screen attachment filenames for suspicious file types."""
        findings: List[ScreeningFinding] = []
        dangerous_extensions = {
            ".exe", ".bat", ".cmd", ".com", ".scr", ".pif",
            ".vbs", ".vbe", ".js", ".jse", ".wsh", ".wsf",
            ".msi", ".msp", ".ps1", ".psm1",
            ".dll", ".sys", ".drv",
        }
        double_extension_pattern = re.compile(
            r"\.\w{2,4}\.(exe|bat|cmd|scr|vbs|js|ps1|msi)$", re.IGNORECASE
        )

        for filename in filenames:
            ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

            if ext in dangerous_extensions:
                findings.append(
                    ScreeningFinding(
                        category=ThreatCategory.MALWARE_PAYLOAD,
                        severity="CRITICAL",
                        confidence=0.90,
                        description=f"Dangerous file type: {ext}",
                        matched_text=filename,
                        remediation="Do not open this attachment. Quarantine immediately.",
                    )
                )

            if double_extension_pattern.search(filename):
                findings.append(
                    ScreeningFinding(
                        category=ThreatCategory.MALWARE_PAYLOAD,
                        severity="CRITICAL",
                        confidence=0.92,
                        description="Double extension detected (common malware disguise)",
                        matched_text=filename,
                        remediation="This file uses a double extension to hide its true type.",
                    )
                )
        return findings

    def _calculate_risk_score(self, findings: List[ScreeningFinding]) -> float:
        """Calculate risk score from findings using weighted severity."""
        if not findings:
            return 0.0

        import math

        total = sum(
            self.SEVERITY_WEIGHTS.get(f.severity, 5.0) * f.confidence
            for f in findings
        )
        # Reason: logarithmic scaling prevents a flood of LOW findings
        # from producing an artificially high score
        return min(100.0, (math.log(total + 1) / math.log(101)) * 100)

    def _determine_verdict(
        self, risk_score: float, findings: List[ScreeningFinding]
    ) -> Verdict:
        """Determine screening verdict from risk score and findings."""
        has_critical = any(f.severity == "CRITICAL" for f in findings)

        if has_critical or risk_score >= 70:
            return Verdict.MALICIOUS
        if risk_score >= 30:
            return Verdict.SUSPICIOUS
        return Verdict.SAFE

    @staticmethod
    def _redact(text: str) -> str:
        """Redact sensitive text, showing only first/last 4 chars."""
        if len(text) <= 10:
            return "***REDACTED***"
        return f"{text[:4]}{'*' * (len(text) - 8)}{text[-4:]}"
