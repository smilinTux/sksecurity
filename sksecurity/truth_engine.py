"""
SKSecurity Truth Engine — Neuresthetics seed integration.

Uses the Steel Man Collider to evaluate the truthfulness of security
decisions, verify threat assessments, and generate adversarial reasoning
prompts that help an AI *explain* its security verdicts rigorously.

Import chain: skseed (preferred) > skmemory (legacy) > built-in fallback.
The engine always works — it degrades gracefully when dependencies are missing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional

# ──────────────────────────────────────────────────────────
# Lazy import: try skseed first, then skmemory, then fallback
# ──────────────────────────────────────────────────────────
_BACKEND: Optional[str] = None


def _resolve_backend() -> str:
    """Determine which backend is available: skseed > skmemory > builtin."""
    global _BACKEND
    if _BACKEND is not None:
        return _BACKEND

    try:
        import skseed.framework  # noqa: F401
        _BACKEND = "skseed"
    except ImportError:
        try:
            import skmemory.steelman  # noqa: F401
            _BACKEND = "skmemory"
        except ImportError:
            _BACKEND = "builtin"

    return _BACKEND


@dataclass
class TruthVerdict:
    """Result of running a security claim through the truth engine.

    Attributes:
        claim: The original security assertion.
        steel_man: Strongest version of the claim.
        inversion: Strongest counter-argument.
        invariants: Truths that survived collision.
        coherence: Internal consistency score 0-1.
        grade: Overall truth grade.
        reasoning_prompt: Full LLM prompt for deeper analysis.
    """

    claim: str
    steel_man: str = ""
    inversion: str = ""
    invariants: List[str] = field(default_factory=list)
    coherence: float = 0.0
    grade: str = "ungraded"
    reasoning_prompt: str = ""

    def is_trustworthy(self, threshold: float = 0.7) -> bool:
        """Return True when coherence exceeds *threshold*.

        Args:
            threshold: Minimum coherence required.

        Returns:
            bool: Whether the claim passes the trust check.
        """
        return self.coherence >= threshold

    def summary(self) -> str:
        """Human-readable one-liner.

        Returns:
            str: Formatted summary.
        """
        status = "TRUSTED" if self.is_trustworthy() else "SUSPECT"
        return (
            f"[{status}] (coherence={self.coherence:.2f}, grade={self.grade}) "
            f"{self.claim[:80]}"
        )


class TruthEngine:
    """Bridge between SKSecurity and the Neuresthetics Steel Man Collider.

    Import priority: skseed (standalone logic kernel) > skmemory (legacy
    location) > built-in lightweight fallback.

    Args:
        framework_path: Optional path to a custom ``seed.json``.
    """

    def __init__(self, framework_path: Optional[str] = None) -> None:
        self._framework: Any = None
        self._framework_path = framework_path
        self._backend = _resolve_backend()

        if self._backend == "skseed":
            from skseed.framework import load_seed_framework, get_default_framework

            if framework_path:
                self._framework = load_seed_framework(framework_path)
            if self._framework is None:
                self._framework = get_default_framework()

        elif self._backend == "skmemory":
            from skmemory.steelman import load_seed_framework, get_default_framework

            if framework_path:
                self._framework = load_seed_framework(framework_path)
            if self._framework is None:
                self._framework = get_default_framework()

    @property
    def is_full_engine(self) -> bool:
        """True when the full Neuresthetics seed framework is loaded.

        Returns:
            bool: Whether skseed or skmemory integration is active.
        """
        return self._backend in ("skseed", "skmemory") and self._framework is not None

    @property
    def backend(self) -> str:
        """Which backend is being used: skseed, skmemory, or builtin."""
        return self._backend

    def verify_threat(self, threat_description: str) -> TruthVerdict:
        """Run a threat assessment through the collider.

        Takes a threat claim (e.g. "This file contains a backdoor") and
        builds the strongest possible case *for* and *against* it, then
        returns the invariant truth.

        Args:
            threat_description: The threat claim to verify.

        Returns:
            TruthVerdict: Dialectic analysis of the claim.
        """
        prompt = self._build_prompt(
            threat_description,
            context="security threat assessment",
        )
        return TruthVerdict(
            claim=threat_description,
            reasoning_prompt=prompt,
            grade="pending-llm",
        )

    def verify_scan_result(self, scan_summary: str, risk_score: float) -> TruthVerdict:
        """Verify a full scan result is coherent.

        Args:
            scan_summary: The scan summary string.
            risk_score: The calculated risk score.

        Returns:
            TruthVerdict: Dialectic analysis of the scan.
        """
        claim = (
            f"Security scan concluded: '{scan_summary}' "
            f"with risk score {risk_score:.1f}/100."
        )
        prompt = self._build_prompt(
            claim,
            context="scan result verification",
        )
        return TruthVerdict(
            claim=claim,
            reasoning_prompt=prompt,
            grade="pending-llm",
        )

    def verify_quarantine_decision(
        self, file_path: str, threat_type: str, severity: str
    ) -> TruthVerdict:
        """Verify a quarantine decision is justified.

        Args:
            file_path: Path of quarantined file.
            threat_type: Classification of threat.
            severity: Severity level.

        Returns:
            TruthVerdict: Dialectic analysis of the decision.
        """
        claim = (
            f"File '{file_path}' should be quarantined because it contains "
            f"a {severity}-severity {threat_type} threat."
        )
        prompt = self._build_prompt(
            claim,
            context="quarantine justification",
        )
        return TruthVerdict(
            claim=claim,
            reasoning_prompt=prompt,
            grade="pending-llm",
        )

    def explain_verdict(self, screening_verdict: str, content_snippet: str) -> str:
        """Generate an LLM prompt that explains *why* a screening verdict was given.

        Useful for the email screener and secret guard modules.

        Args:
            screening_verdict: The verdict (e.g. BLOCK, WARN, ALLOW).
            content_snippet: Excerpt of the screened content.

        Returns:
            str: LLM-ready reasoning prompt.
        """
        claim = (
            f"The content was assigned verdict '{screening_verdict}'. "
            f"Content excerpt: {content_snippet[:200]}"
        )
        return self._build_prompt(claim, context="screening explanation")

    def _build_prompt(self, proposition: str, context: str = "") -> str:
        """Build a reasoning prompt using the seed framework or fallback.

        Args:
            proposition: The claim to evaluate.
            context: Additional context label.

        Returns:
            str: Formatted reasoning prompt.
        """
        if self._framework is not None:
            return self._framework.to_reasoning_prompt(proposition)

        return self._fallback_prompt(proposition, context)

    @staticmethod
    def _fallback_prompt(proposition: str, context: str) -> str:
        """Minimal built-in reasoning prompt when no framework package is available.

        Args:
            proposition: The claim to evaluate.
            context: The analysis context.

        Returns:
            str: Formatted fallback prompt.
        """
        return (
            f"=== SKSecurity Truth Analysis ({context}) ===\n\n"
            f"PROPOSITION: {proposition}\n\n"
            "INSTRUCTIONS:\n"
            "1. Steel-man this claim: build the STRONGEST possible "
            "version of it.\n"
            "2. Invert: build the STRONGEST counter-argument.\n"
            "3. Collide: identify contradictions between the two.\n"
            "4. Extract invariants: what truths remain regardless of "
            "perspective?\n"
            "5. Grade: invariant / strong / partial / weak / collapsed.\n\n"
            "Return your analysis as structured JSON with keys: "
            "steel_man, inversion, contradictions, invariants, "
            "coherence_score (0-1), truth_grade.\n"
        )
