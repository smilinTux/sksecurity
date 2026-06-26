"""RFC-0001 P4 — the honesty self-report learns the DM ratchet LEVEL.

``dm_ratchet_surface_for`` must report not just *which suite* a 1:1 conversation
negotiated, but *how much forward secrecy* the running session actually gives:

    * L2-oneshot — today's stateless single-prekey hybrid seal (PQ at the prekey
      only, no forward secrecy beyond prekey rotation);
    * L3-epoch  — the running DmRatchet (per-epoch hybrid-KEM rekey → FS + PCS).

Honesty discipline (sk-standards CRYPTOGRAPHY_STANDARD): never "quantum-proof"
/ "quantum-safe" / "unbreakable"; a classical KEM stays HNDL-exposed regardless
of ratchet level.
"""

from __future__ import annotations

from sksecurity.pqc_report import build_report, dm_ratchet_surface_for

_HYBRID = "x25519-mlkem768"
_CLASSICAL = "x25519-pgp-wrap-v1"
_FORBIDDEN = ("quantum-proof", "quantum-safe", "unbreakable")


def test_returns_dm_four_tuple():
    tup = dm_ratchet_surface_for(_HYBRID, ratchet_level="L3-epoch", epoch=3)
    assert isinstance(tup, tuple) and len(tup) == 4
    surface, component, suite_id, note = tup
    assert surface == "dm"
    assert suite_id == _HYBRID
    assert isinstance(note, str) and note


def test_l3_epoch_reports_fs_pcs_and_epoch_number():
    _, _, suite_id, note = dm_ratchet_surface_for(
        _HYBRID, ratchet_level="L3-epoch", epoch=7
    )
    low = note.lower()
    assert "epoch-ratchet" in low
    assert "fs + pcs" in low
    assert "x25519+ml-kem-768" in low
    assert "rekey per epoch" in low
    assert "epoch 7" in low  # the actual epoch number is surfaced
    assert suite_id == _HYBRID


def test_l2_oneshot_reports_no_running_ratchet():
    _, _, _, note = dm_ratchet_surface_for(_HYBRID, ratchet_level="L2-oneshot")
    low = note.lower()
    assert "one-shot" in low
    assert "no running ratchet" in low
    assert "published prekey only" in low


def test_classical_suite_is_hndl_exposed_regardless_of_level():
    for level in ("L2-oneshot", "L3-epoch"):
        _, _, suite_id, note = dm_ratchet_surface_for(
            _CLASSICAL, ratchet_level=level, epoch=4
        )
        assert suite_id == _CLASSICAL
        assert "hndl-exposed" in note.lower(), (level, note)


def test_no_forbidden_words_any_level_any_suite():
    for suite in (_HYBRID, _CLASSICAL):
        for level in ("L2-oneshot", "L3-epoch"):
            _, _, _, note = dm_ratchet_surface_for(suite, ratchet_level=level, epoch=1)
            low = note.lower()
            for bad in _FORBIDDEN:
                assert bad not in low, (suite, level, bad)


def test_l3_hybrid_surface_resolves_quantum_resistant_in_report():
    """Fed through build_report, an L3 hybrid DM resolves to hybrid-pq."""
    tup = dm_ratchet_surface_for(_HYBRID, ratchet_level="L3-epoch", epoch=2)
    rpt = build_report(surfaces=[tup])
    s = rpt["surfaces"][0]
    assert s["surface"] == "dm"
    assert s["status"] == "hybrid-pq"
    assert s["quantum_resistant"] is True
    assert "FIPS 203" in s["fips_refs"]


def test_classical_dm_surface_not_quantum_resistant_in_report():
    tup = dm_ratchet_surface_for(_CLASSICAL, ratchet_level="L3-epoch", epoch=2)
    rpt = build_report(surfaces=[tup])
    s = rpt["surfaces"][0]
    assert s["status"] == "classical"
    assert s["quantum_resistant"] is False


def test_unknown_level_falls_back_to_l2_oneshot():
    _, _, _, note = dm_ratchet_surface_for(_HYBRID, ratchet_level="bogus")
    assert "one-shot" in note.lower()
