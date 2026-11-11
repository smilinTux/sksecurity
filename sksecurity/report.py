"""Where findings go. Every sweep calls :func:`report`.

ITIL reporter (docs/sweeps/reporting.md), modelled on skcapstone
``service_health._create_incident_for_down_service``:

* critical and high findings each get their own incident (sev2 / sev3),
  found-open-first by the ``fp:<fingerprint>`` tag so a re-run never
  duplicates; at most :data:`MAX_NEW_PER_RUN` new ones per run, the rest are
  rolled up;
* medium and low findings roll up into ONE open sev4 incident per
  (sweep, host), updated in place;
* an open finding not seen in the run gets a "not seen" event, never an
  auto-close;
* one sk-alert per run, not per finding;
* incident text carries location, class, rule and remediation, never a value.

skcapstone/skcoord are optional: without them a non-dry run reports
``error="itil-unavailable"`` and files nothing. ``dry_run=True`` (the CLI
default) touches nothing at all.
"""

from __future__ import annotations

import hashlib
import logging
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .findings import Finding

logger = logging.getLogger("sksecurity.report")

MAX_NEW_PER_RUN = 20
MAX_ROLLUP_LINES = 60
AGENT = "sksecurity"
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEV_TO_ITIL = {"critical": "sev2", "high": "sev3"}
_NOT_SEEN = "not seen in sweep at"
_OPEN = {"detected", "acknowledged", "investigating", "escalated"}
#: Classes about the sweep itself, not a finding in the estate.
_META_TRUNCATED = "sweep.truncated"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _itil_home() -> Path:
    """ITIL shared root. ``SKSECURITY_ITIL_HOME`` wins (tests, odd nodes), then
    ``SKCAPSTONE_SHARED_ROOT`` (what skcapstone itself honours), then
    ``~/.skcapstone``."""
    for var in ("SKSECURITY_ITIL_HOME", "SKCAPSTONE_SHARED_ROOT"):
        v = os.environ.get(var)
        if v:
            return Path(v).expanduser()
    return Path("~/.skcapstone").expanduser()


def _manager():
    """ITILManager from skcoord (or its skcapstone shim), or None."""
    try:
        from skcoord.itil import ITILManager
    except Exception:
        try:
            from skcapstone.itil import ITILManager  # type: ignore[no-redef]
        except Exception:
            return None
    return ITILManager(_itil_home())


def _sort_key(f: Finding):
    return (_SEV_RANK.get(f.severity, 9), f.klass, f.location, f.fingerprint)


def _incident_text(f: Finding) -> str:
    """Impact text: where, what, how to fix. Never a value."""
    parts = [
        f"{f.summary}.",
        f"location={f.location}",
        f"class={f.klass}",
        f"rule={f.rule or 'n/a'}",
        f"host={f.host}",
    ]
    if f.kedb:
        parts.append(f"kedb={f.kedb}")
    if f.remediation:
        parts.append(f"remediation: {f.remediation}")
    return "; ".join(parts)


def _tags(f: Finding, sweep: str) -> List[str]:
    tags = ["sksecurity", f"sweep:{sweep}", f"fp:{f.fingerprint}",
            f"class:{f.klass}", f"host:{f.host}"]
    if f.kedb:
        tags.append(f"kedb:{f.kedb}")
    return tags


def _open_incidents(mgr) -> list:
    try:
        return [i for i in mgr.list_incidents() if i.status.value in _OPEN]
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("could not list ITIL incidents: %s", exc)
        return []


def _last_note(inc) -> str:
    for entry in reversed(inc.timeline or []):
        note = entry.get("note") or ""
        if note:
            return note
    return ""


def _rollup_lines(items: List[Finding]) -> List[str]:
    lines = [f"[{f.severity}] {f.klass} {f.location} rule={f.rule or 'n/a'}"
             for f in items[:MAX_ROLLUP_LINES]]
    if len(items) > MAX_ROLLUP_LINES:
        lines.append(f"... and {len(items) - MAX_ROLLUP_LINES} more")
    return lines


def _summary(findings: List[Finding], sweep: str, dry_run: bool) -> Dict[str, Any]:
    by_sev: Dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return {"sweep": sweep, "total": len(findings), "by_severity": by_sev,
            "filed": [], "dry_run": dry_run}


def report(findings: List[Finding], sweep: str, dry_run: bool = True) -> Dict[str, Any]:
    """File findings (dedup by fingerprint) and return a run summary.

    Returns at least: {"sweep", "total", "by_severity", "filed", "dry_run"}.
    ``filed`` is the list of NEWLY created incident ids; ``updated`` lists the
    existing incidents that received an event.
    """
    out = _summary(findings, sweep, dry_run)
    host = socket.gethostname()
    urgent = sorted((f for f in findings if f.severity in _SEV_TO_ITIL), key=_sort_key)
    minor = sorted((f for f in findings if f.severity not in _SEV_TO_ITIL), key=_sort_key)
    out["plan"] = {"urgent": len(urgent), "rollup": len(minor), "over_cap": 0}

    if dry_run:
        return out

    mgr = _manager()
    if mgr is None:
        out["error"] = "itil-unavailable"
        return out

    open_incs = _open_incidents(mgr)
    by_fp: Dict[str, Any] = {}
    rollup = None
    for inc in open_incs:
        tags = set(inc.tags)
        if "sksecurity" not in tags or f"sweep:{sweep}" not in tags:
            continue
        if f"host:{host}" not in tags:
            continue
        if "rollup" in tags:
            rollup = rollup or inc
        for t in tags:
            if t.startswith("fp:"):
                by_fp[t[3:]] = inc

    filed: List[str] = []
    updated: List[str] = []
    created_urgent = 0
    spill: List[Finding] = []

    for f in urgent:
        if f.fingerprint in by_fp:
            continue  # find-open-first: already tracked, no event churn
        if created_urgent >= MAX_NEW_PER_RUN:
            spill.append(f)
            continue
        try:
            inc = mgr.create_incident(
                title=f"sksecurity {sweep}: {f.klass} at {f.location}",
                severity=_SEV_TO_ITIL[f.severity], source="sksecurity",
                affected_services=[f"sksecurity.{sweep}"], impact=_incident_text(f),
                managed_by=os.environ.get("SKAGENT") or "lumina", created_by=AGENT,
                tags=_tags(f, sweep))
            filed.append(inc.id)
            created_urgent += 1
            by_fp[f.fingerprint] = inc
        except Exception as exc:
            logger.warning("could not file incident for %s: %s", f.fingerprint, exc)
            spill.append(f)
    out["plan"]["over_cap"] = len(spill)

    # Roll-up of medium/low plus any critical/high that did not get its own.
    rolled = minor + sorted(spill, key=_sort_key)
    if rolled:
        n_minor = len(minor)
        title = f"sksecurity {sweep} sweep on {host}: {n_minor} medium/low findings"
        set_id = hashlib.sha256("\n".join(sorted(f.fingerprint for f in rolled)).encode()
                                ).hexdigest()[:8]
        note_lines = [f"{n_minor} medium/low findings (set {set_id}) at {_now()}"]
        if spill:
            note_lines.append(
                f"{len(spill)} critical/high findings are included here because the "
                f"per-run cap of {MAX_NEW_PER_RUN} new incidents was reached.")
        note_lines += _rollup_lines(rolled)
        note = "\n".join(note_lines)
        try:
            if rollup is None:
                inc = mgr.create_incident(
                    title=title, severity="sev4", source="sksecurity",
                    affected_services=[f"sksecurity.{sweep}"], impact=note,
                    managed_by=os.environ.get("SKAGENT") or "lumina", created_by=AGENT,
                    tags=["sksecurity", f"sweep:{sweep}", "rollup", f"host:{host}"])
                filed.append(inc.id)
                rollup = inc
            elif f"(set {set_id})" not in _last_note(rollup):
                mgr.update_incident(rollup.id, AGENT, note=note)
                updated.append(rollup.id)
            if spill and rollup.severity.value == "sev4":
                mgr.update_incident(rollup.id, AGENT, severity="sev3",
                                    note="critical/high findings spilled into this roll-up")
                if rollup.id not in updated and rollup.id not in filed:
                    updated.append(rollup.id)
            out["rollup"] = rollup.id
        except Exception as exc:
            logger.warning("could not file roll-up: %s", exc)

    # Open finding incidents no longer seen: event only, never auto-close.
    # A partial run (time budget) cannot say "gone".
    seen = {f.fingerprint for f in findings}
    partial = any(f.klass == _META_TRUNCATED for f in findings)
    not_seen: List[str] = []
    if not partial:
        for fp, inc in by_fp.items():
            if fp in seen or "rollup" in inc.tags:
                continue
            if _NOT_SEEN in _last_note(inc):
                continue
            try:
                mgr.update_incident(inc.id, AGENT, note=f"{_NOT_SEEN} {_now()} (host {host}); "
                                    "verify and resolve manually")
                not_seen.append(inc.id)
            except Exception as exc:
                logger.warning("could not annotate %s: %s", inc.id, exc)

    out.update(filed=filed, updated=updated, not_seen=not_seen)

    if findings:
        try:
            from . import integration
            worst = min((f.severity for f in findings), key=lambda s: _SEV_RANK.get(s, 9))
            integration.alert(
                "sweep_summary",
                {"sweep": sweep, "host": host, "total": len(findings),
                 "by_severity": out["by_severity"], "new_incidents": len(filed),
                 "not_seen": len(not_seen)},
                level=integration.level_for_severity(worst))
        except Exception as exc:
            logger.warning("sk-alert failed: %s", exc)
    return out
