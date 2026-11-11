"""sksecurity <-> skcapstone - optional integration adapter.

When ``skcapstone`` is installed (and ``SK_STANDALONE`` is unset) this adapter
publishes detections on the mesh-wide **sk-alert** bus.  When skcapstone is
absent, or ``SK_STANDALONE`` is set, it only writes to the local logger.  It
never registers itself, never writes a scheduler job and never touches the
skcapstone registry.

Default-on by presence, native fallback - see
``skcapstone/docs/ADR-optional-integration-backbone.md``.  ``skcapstone`` is a
soft dependency in the optional ``[skcapstone]`` extra; never imported hard.

Public API:
    is_present()                       -> bool
    level_for_severity(severity)       -> str  (sksecurity → sk-alert level)
    alert(event, payload, level)       -> bool

Topic convention: ``sksecurity.<severity>`` (severity ∈ info|warn|error|
critical); the detection's event name/type travels in the payload.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger("sksecurity.integration")

#: Service name - alert topic prefix and discovery registry key.
SERVICE = "sksecurity"

# Optional import - never a hard dependency.
try:
    from skcapstone import sdk as _sdk
except Exception:
    _sdk = None  # type: ignore[assignment]

#: sksecurity severities → canonical sk-alert levels.
_SEVERITY_TO_LEVEL = {
    "critical": "critical",
    "high": "error",
    "medium": "warn",
    "low": "info",
}
#: sk-alert level → logging method (native fallback).
_LOG_METHOD = {"info": "info", "warn": "warning", "error": "error", "critical": "critical"}
_NOTIFY_LEVELS = frozenset({"warn", "error", "critical"})


def is_present() -> bool:
    """True iff skcapstone integration should be used (package present,
    ``SK_STANDALONE`` unset, SDK reporting available). Failures → False."""
    if os.environ.get("SK_STANDALONE"):
        return False
    if _sdk is None:
        return False
    try:
        return bool(_sdk.is_available())
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("skcapstone present-check failed: %s", exc)
        return False


def level_for_severity(severity: str) -> str:
    """Map a sksecurity severity (critical|high|medium|low) to an sk-alert
    level (critical|error|warn|info). Unknown severities map to ``warn``."""
    return _SEVERITY_TO_LEVEL.get((severity or "").lower(), "warn")


def alert(event: str, payload: dict[str, Any], level: str = "info") -> bool:
    """Share a detection on the sk-alert bus when present, else log locally.

    The published topic is ``sksecurity.<severity>`` (so ``skcapstone alerts``,
    which subscribes to ``*.error`` / ``*.critical`` / ``*.warn``, surfaces it).
    The detection's event name/type is carried in the payload ``event`` field.

    Args:
        event: Detection event name/type (e.g. ``"process"``, ``"secret_leak"``).
        payload: JSON-serialisable detail body.
        level: ``info | warn | error | critical`` (use
            :func:`level_for_severity` to convert from a sksecurity severity).

    Returns:
        ``True`` if published to the shared bus, ``False`` on native fallback.
    """
    body = {"event": event, **dict(payload)}
    if is_present():
        try:
            return bool(
                _sdk.alert(
                    f"{SERVICE}.{level}",
                    body,
                    level=level,
                    notify=level in _NOTIFY_LEVELS,
                )
            )
        except Exception as exc:
            logger.warning("sk-alert publish failed, logging locally: %s", exc)

    method = getattr(logger, _LOG_METHOD.get(level, "info"))
    method("[%s.%s] %s", SERVICE, level, body)
    return False
