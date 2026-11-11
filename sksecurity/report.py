"""Where findings go. Every sweep calls :func:`report`.

This is the contract stub: it returns a summary and, unless ``dry_run`` is
False and the ITIL reporter is implemented, files nothing. The ITIL reporter
(step 3) replaces the body of :func:`report` and keeps its signature.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .findings import Finding


def report(findings: List[Finding], sweep: str, dry_run: bool = True) -> Dict[str, Any]:
    """File findings (dedup by fingerprint) and return a run summary.

    Returns at least: {"sweep", "total", "by_severity", "filed", "dry_run"}.
    """
    by_sev: Dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return {"sweep": sweep, "total": len(findings), "by_severity": by_sev,
            "filed": [], "dry_run": dry_run}
