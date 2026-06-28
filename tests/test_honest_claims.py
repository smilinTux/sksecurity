"""Tests for SKSecurity HonestClaims scanner — the no-overclaim gate.

Honesty discipline (sk-standards CRYPTOGRAPHY_STANDARD): never "quantum-proof"
/ "quantum-safe" / "unbreakable" / "uncrackable" / "100% secure"; a classical
KEM stays harvest-now-decrypt-later exposed regardless, and a hybrid scheme is
only as strong as its *strongest surviving leg* (FIPS 203/204 cited). This
scanner enforces that discipline mechanically.
"""

import tempfile
from pathlib import Path

import pytest

from sksecurity.honest_claims import (
    HonestClaimsScanner,
    ClaimScanResult,
    ClaimFinding,
)


@pytest.fixture
def scanner():
    return HonestClaimsScanner()


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


# ─── Expected use: detect a real violation ──────────────────────────


class TestDetectViolations:
    def test_quantum_proof_is_flagged(self, scanner):
        findings = scanner.scan_text("Our protocol is quantum-proof.")
        assert len(findings) == 1
        assert findings[0].claim == "quantum-proof"

    def test_quantum_safe_is_flagged(self, scanner):
        findings = scanner.scan_text("We ship quantum-safe encryption today.")
        assert any(f.claim == "quantum-safe" for f in findings)

    def test_unbreakable_is_flagged(self, scanner):
        findings = scanner.scan_text("This cipher is unbreakable.")
        assert any(f.claim == "unbreakable" for f in findings)

    def test_uncrackable_is_flagged(self, scanner):
        findings = scanner.scan_text("An uncrackable vault for your keys.")
        assert any(f.claim == "uncrackable" for f in findings)

    def test_hundred_percent_secure_is_flagged(self, scanner):
        findings = scanner.scan_text("Your data is 100% secure with us.")
        assert any(f.claim == "100% secure" for f in findings)

    def test_hundred_percent_secure_word_variant(self, scanner):
        findings = scanner.scan_text("We are 100 percent secure.")
        assert any(f.claim == "100% secure" for f in findings)

    def test_military_grade_as_security_claim_is_flagged(self, scanner):
        findings = scanner.scan_text("Protected by military-grade encryption.")
        assert any(f.claim == "military-grade" for f in findings)

    def test_space_variant_quantum_proof(self, scanner):
        findings = scanner.scan_text("It is quantum proof, period.")
        assert any(f.claim == "quantum-proof" for f in findings)

    def test_finding_carries_line_and_source(self, scanner):
        text = "line one\nour crypto is unbreakable\nline three"
        findings = scanner.scan_text(text, source="ad.md")
        assert isinstance(findings[0], ClaimFinding)
        assert findings[0].file_path == "ad.md"
        assert findings[0].line_number == 2


# ─── Pass on honest negations ───────────────────────────────────────


class TestHonestNegations:
    def test_never_quantum_proof(self, scanner):
        assert scanner.scan_text(
            'We say "post-quantum," never quantum-proof.'
        ) == []

    def test_not_unbreakable(self, scanner):
        assert scanner.scan_text("No cipher is ever truly unbreakable.") == []

    def test_no_such_thing_as_uncrackable(self, scanner):
        assert scanner.scan_text(
            "There is no such thing as an uncrackable system."
        ) == []

    def test_not_100_percent_secure(self, scanner):
        assert scanner.scan_text("Nothing is 100% secure; we reduce risk.") == []

    def test_cross_clause_negation(self, scanner):
        # The negating word follows the phrase but in the same sentence.
        assert scanner.scan_text(
            'Avoid "quantum-safe" and "unbreakable"; never imply that.'
        ) == []

    def test_cross_line_negation_within_sentence(self, scanner):
        # "No ... quantum-proof claim is made." wrapped across a newline.
        text = "No global / end-to-end /\nquantum-proof claim is made here."
        assert scanner.scan_text(text) == []

    def test_quoted_phrase_is_meta_reference(self, scanner):
        # Listing the forbidden token in quotes is a meta-reference, not a claim.
        text = '"quantum-proof" / "unbreakable" / "quantum-safe"'
        assert scanner.scan_text(text) == []

    def test_forbidden_list_variable(self, scanner):
        assert scanner.scan_text(
            '_FORBIDDEN = ("quantum-proof", "unbreakable")'
        ) == []

    def test_positive_claim_after_unrelated_negation_still_flags(self, scanner):
        # Negation belongs to the previous sentence; the claim is real.
        text = "This is not a toy. Our crypto is quantum-proof."
        findings = scanner.scan_text(text)
        assert any(f.claim == "quantum-proof" for f in findings)

    def test_military_grade_without_security_context_ok(self, scanner):
        # "military-grade titanium" is a materials claim, not a security claim.
        assert scanner.scan_text("Built from military-grade titanium.") == []


# ─── "Open Quantum Safe" proper noun (the OQS project / liboqs) ─────


class TestOpenQuantumSafeProperNoun:
    """"Open Quantum Safe" / "open-quantum-safe" is the name of the OQS
    project (liboqs), not a "quantum-safe" security claim. PQC repos cite it
    constantly; the gate must not fire on the proper noun."""

    def test_open_quantum_safe_project_name(self, scanner):
        assert scanner.scan_text(
            "The ML-KEM-768 leg binds liboqs from Open Quantum Safe."
        ) == []

    def test_open_quantum_safe_hyphenated_url(self, scanner):
        assert scanner.scan_text(
            "via [liboqs](https://github.com/open-quantum-safe/liboqs)"
        ) == []

    def test_open_quantum_safe_underscore_variant(self, scanner):
        assert scanner.scan_text("see the open_quantum_safe org on GitHub") == []

    def test_real_quantum_safe_claim_still_flags(self, scanner):
        # A genuine "quantum-safe" claim (not the proper noun) must still fire.
        findings = scanner.scan_text("Our protocol is quantum-safe today.")
        assert any(f.claim == "quantum-safe" for f in findings)


# ─── Rust / cargo build dir is skipped ──────────────────────────────


class TestCargoTargetSkipped:
    def test_target_build_dir_ignored(self, temp_dir):
        target = temp_dir / "target" / "debug"
        target.mkdir(parents=True)
        (target / "libfoo.rlib").write_text("quantum-proof unbreakable")
        (temp_dir / "README.md").write_text("Post-quantum, FIPS 203.")
        result = HonestClaimsScanner().scan_directory(temp_dir)
        assert not result.has_violations


# ─── Inline allow directive ─────────────────────────────────────────


class TestInlineDirective:
    def test_noqa_directive_suppresses(self, scanner):
        text = "Our crypto is unbreakable  # honest-claims: allow"
        assert scanner.scan_text(text) == []

    def test_noqa_alt_form(self, scanner):
        text = "marketing said quantum-proof  # noqa: honest-claims"
        assert scanner.scan_text(text) == []


# ─── Allowlist file ─────────────────────────────────────────────────


class TestAllowlistFile:
    def test_allowlisted_file_is_skipped(self, temp_dir):
        bad = temp_dir / "legacy_marketing.md"
        bad.write_text("Our product is 100% secure and unbreakable.")
        allow = temp_dir / ".honestclaims-allow"
        allow.write_text("# legacy copy, scheduled for rewrite\nlegacy_marketing.md\n")

        scanner = HonestClaimsScanner(allowlist_file=allow)
        result = scanner.scan_directory(temp_dir)
        assert not result.has_violations

    def test_non_allowlisted_file_still_flagged(self, temp_dir):
        (temp_dir / "fresh.md").write_text("Truly unbreakable encryption.")
        allow = temp_dir / ".honestclaims-allow"
        allow.write_text("legacy_marketing.md\n")

        scanner = HonestClaimsScanner(allowlist_file=allow)
        result = scanner.scan_directory(temp_dir)
        assert result.has_violations

    def test_inline_allowlist_argument(self, temp_dir):
        (temp_dir / "a.md").write_text("unbreakable forever")
        scanner = HonestClaimsScanner(allowlist=["a.md"])
        assert scanner.scan_file(temp_dir / "a.md") == []


# ─── Directory scan + result object ─────────────────────────────────


class TestDirectoryScan:
    def test_scan_directory_returns_result(self, temp_dir):
        (temp_dir / "good.md").write_text("Post-quantum, hybrid where it counts.")
        (temp_dir / "bad.md").write_text("quantum-proof and uncrackable!")
        scanner = HonestClaimsScanner()
        result = scanner.scan_directory(temp_dir)
        assert isinstance(result, ClaimScanResult)
        assert result.has_violations
        assert result.files_scanned >= 2

    def test_result_to_dict_roundtrips(self, temp_dir):
        (temp_dir / "bad.md").write_text("unbreakable")
        result = HonestClaimsScanner().scan_directory(temp_dir)
        d = result.to_dict()
        assert d["has_violations"] is True
        assert d["findings"][0]["claim"] == "unbreakable"

    def test_format_report_is_string(self, temp_dir):
        (temp_dir / "bad.md").write_text("100% secure")
        result = HonestClaimsScanner().scan_directory(temp_dir)
        report = result.format_report()
        assert "100% secure" in report

    def test_clean_directory_no_violations(self, temp_dir):
        (temp_dir / "honest.md").write_text(
            "ML-KEM (FIPS 203) gives post-quantum confidentiality on the "
            "PQ leg; the classical leg stays HNDL-exposed. Never quantum-proof."
        )
        result = HonestClaimsScanner().scan_directory(temp_dir)
        assert not result.has_violations

    def test_binary_and_skip_dirs_ignored(self, temp_dir):
        gitdir = temp_dir / ".git"
        gitdir.mkdir()
        (gitdir / "COMMIT_EDITMSG").write_text("unbreakable")
        (temp_dir / "logo.png").write_bytes(b"\x89PNG unbreakable")
        result = HonestClaimsScanner().scan_directory(temp_dir)
        assert not result.has_violations


# ─── Repo self-test: this repo must pass its own gate ───────────────


def test_this_repo_passes_its_own_gate():
    """The no-overclaim gate must be green on the repo that ships it.

    Honest-discipline docs *quote* the forbidden tokens to forbid them;
    those are negations/meta references, not claims. If this fails, either
    a real overclaim was introduced or an honest doc needs an allowlist
    entry / negation marker.
    """
    repo_root = Path(__file__).resolve().parent.parent
    allow = repo_root / ".honestclaims-allow"
    scanner = HonestClaimsScanner(
        allowlist_file=allow if allow.exists() else None
    )
    result = scanner.scan_directory(repo_root)
    assert not result.has_violations, result.format_report()
