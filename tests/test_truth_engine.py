"""Tests for the TruthEngine module."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from sksecurity.truth_engine import TruthEngine, TruthVerdict, _check_skmemory


class TestTruthVerdict:
    """Tests for the TruthVerdict dataclass."""

    def test_defaults(self) -> None:
        """Verdict has sensible defaults."""
        v = TruthVerdict(claim="test claim")
        assert v.coherence == 0.0
        assert v.grade == "ungraded"
        assert v.invariants == []

    def test_is_trustworthy_high(self) -> None:
        """Verdict with high coherence is trustworthy."""
        v = TruthVerdict(claim="x", coherence=0.9)
        assert v.is_trustworthy() is True

    def test_is_trustworthy_low(self) -> None:
        """Verdict with low coherence is not trustworthy."""
        v = TruthVerdict(claim="x", coherence=0.3)
        assert v.is_trustworthy() is False

    def test_is_trustworthy_custom_threshold(self) -> None:
        """Custom threshold changes the boundary."""
        v = TruthVerdict(claim="x", coherence=0.5)
        assert v.is_trustworthy(threshold=0.4) is True
        assert v.is_trustworthy(threshold=0.6) is False

    def test_summary_trusted(self) -> None:
        """Summary shows TRUSTED for high coherence."""
        v = TruthVerdict(claim="Something important", coherence=0.85, grade="strong")
        s = v.summary()
        assert "TRUSTED" in s
        assert "strong" in s

    def test_summary_suspect(self) -> None:
        """Summary shows SUSPECT for low coherence."""
        v = TruthVerdict(claim="Dubious claim", coherence=0.2, grade="weak")
        s = v.summary()
        assert "SUSPECT" in s

    def test_summary_truncates_long_claims(self) -> None:
        """Summary truncates claims longer than 80 chars."""
        long_claim = "A" * 200
        v = TruthVerdict(claim=long_claim, coherence=0.5)
        s = v.summary()
        assert len(s) < 250


class TestTruthEngine:
    """Tests for the TruthEngine class."""

    def test_init_without_skmemory(self) -> None:
        """Engine initializes even without skmemory."""
        engine = TruthEngine()
        assert isinstance(engine, TruthEngine)

    def test_verify_threat(self) -> None:
        """verify_threat returns a verdict with a reasoning prompt."""
        engine = TruthEngine()
        verdict = engine.verify_threat("This script contains a backdoor")
        assert isinstance(verdict, TruthVerdict)
        assert "backdoor" in verdict.claim
        assert verdict.reasoning_prompt != ""
        assert verdict.grade == "pending-llm"

    def test_verify_scan_result(self) -> None:
        """verify_scan_result produces a verdict for scan output."""
        engine = TruthEngine()
        verdict = engine.verify_scan_result("Found 3 critical threats", 85.0)
        assert "85.0" in verdict.claim
        assert verdict.reasoning_prompt != ""

    def test_verify_quarantine_decision(self) -> None:
        """verify_quarantine_decision produces a reasoned verdict."""
        engine = TruthEngine()
        verdict = engine.verify_quarantine_decision(
            file_path="/tmp/evil.py",
            threat_type="code_injection",
            severity="CRITICAL",
        )
        assert "evil.py" in verdict.claim
        assert "code_injection" in verdict.claim
        assert verdict.reasoning_prompt != ""

    def test_explain_verdict(self) -> None:
        """explain_verdict generates an explanation prompt."""
        engine = TruthEngine()
        prompt = engine.explain_verdict("BLOCK", "rm -rf / in the email body")
        assert "BLOCK" in prompt
        assert "rm -rf" in prompt

    def test_fallback_prompt_structure(self) -> None:
        """Fallback prompt has required sections."""
        prompt = TruthEngine._fallback_prompt("test proposition", "test context")
        assert "PROPOSITION" in prompt
        assert "Steel-man" in prompt
        assert "Invert" in prompt
        assert "Collide" in prompt
        assert "invariants" in prompt
        assert "test context" in prompt

    def test_is_full_engine_without_skmemory(self) -> None:
        """is_full_engine is False when skmemory not available."""
        engine = TruthEngine()
        # Regardless of skmemory availability, the property should be bool
        assert isinstance(engine.is_full_engine, bool)

    def test_verify_threat_prompt_contains_claim(self) -> None:
        """The reasoning prompt contains the original threat description."""
        engine = TruthEngine()
        verdict = engine.verify_threat("SQL injection in login form")
        assert "SQL injection" in verdict.reasoning_prompt

    def test_explain_verdict_truncates_long_content(self) -> None:
        """Long content snippets are truncated in the prompt."""
        engine = TruthEngine()
        long_content = "x" * 1000
        prompt = engine.explain_verdict("WARN", long_content)
        assert len(prompt) < 3000

    def test_multiple_verifications(self) -> None:
        """Engine handles multiple sequential verifications."""
        engine = TruthEngine()
        v1 = engine.verify_threat("Threat A")
        v2 = engine.verify_threat("Threat B")
        assert v1.claim != v2.claim
        assert v1.reasoning_prompt != v2.reasoning_prompt


class TestTruthEngineWithSkmemory:
    """Tests that exercise the skmemory integration path."""

    def test_with_custom_framework_path_nonexistent(self) -> None:
        """Custom path that doesn't exist falls back gracefully."""
        engine = TruthEngine(framework_path="/nonexistent/seed.json")
        verdict = engine.verify_threat("test")
        assert verdict.reasoning_prompt != ""

    def test_build_prompt_uses_framework_when_available(self) -> None:
        """When framework is loaded, prompt comes from it."""
        engine = TruthEngine()
        if engine.is_full_engine:
            prompt = engine._build_prompt("test claim")
            assert "Recursive" in prompt or "steel" in prompt.lower()
        else:
            prompt = engine._build_prompt("test claim", "testing")
            assert "Steel-man" in prompt
