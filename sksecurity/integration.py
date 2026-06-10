"""sksecurity ⇄ skcapstone — optional integration adapter.

sksecurity is a self-contained security scanner.  When ``skcapstone`` is
installed (and ``SK_STANDALONE`` is unset) this adapter shares threat
detections on the mesh-wide **sk-alert** bus — realising the long-standing
"agent-to-agent threat sharing" goal — and registers a daily threat-intel
refresh with the fleet **skscheduler**.  When skcapstone is absent everything
degrades to sksecurity's native behaviour (the local dashboard "Recent Alerts"
feed + the in-process ``SecurityMonitor`` daemon).

Default-on by presence, native fallback — see
``skcapstone/docs/ADR-optional-integration-backbone.md``.  ``skcapstone`` is a
soft dependency in the optional ``[skcapstone]`` extra; never imported hard.

Public API:
    is_present()                       -> bool
    level_for_severity(severity)       -> str  (sksecurity → sk-alert level)
    alert(event, payload, level)       -> bool
    ensure_schedule(interval_hours)    -> bool
    unregister_schedule()              -> bool
    register_self(pid_file)            -> bool

Topic convention: ``sksecurity.<severity>`` (severity ∈ info|warn|error|
critical); the detection's event name/type travels in the payload.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

logger = logging.getLogger("sksecurity.integration")

#: Service name — alert topic prefix and discovery registry key.
SERVICE = "sksecurity"

#: Fleet-scheduler job name for the threat-intel refresh.
INTEL_JOB = "sksecurity_intel_refresh"

# Optional import — never a hard dependency.
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


def ensure_schedule(interval_hours: float = 24.0) -> bool:
    """Register a daily threat-intel refresh with the fleet scheduler.

    Writes a ``jobs.d/sksecurity_intel_refresh.yaml`` drop-in running
    ``sksecurity update`` (pull threat intelligence from configured sources).
    Idempotent. ``True`` if registered with skscheduler, ``False`` when
    skcapstone is absent (the native ``SecurityMonitor`` daemon remains the
    realtime mechanism either way).
    """
    if not is_present():
        return False
    try:
        _sdk.register_job(
            {
                "name": INTEL_JOB,
                "type": "shell",
                "command": "sksecurity update --sources all",
                "every": f"{int(interval_hours * 3600)}s",
                "timeout": 600,
                "notify": "on_failure",
                "notify_level": "warn",
            }
        )
        logger.info("Registered '%s' with skcapstone scheduler (every %.1fh).",
                    INTEL_JOB, interval_hours)
        return True
    except Exception as exc:
        logger.warning("ensure_schedule failed (using native): %s", exc)
        return False


def unregister_schedule() -> bool:
    """Remove the threat-intel refresh drop-in from the fleet scheduler."""
    if _sdk is None:
        return False
    try:
        return bool(_sdk.unregister_job(INTEL_JOB))
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("unregister_schedule failed: %s", exc)
        return False


def register_self(pid_file: Optional[str] = None) -> bool:
    """Advertise sksecurity to skcapstone's discovery registry, if present."""
    if not is_present():
        return False
    try:
        _sdk.register_service(SERVICE, pid_file=pid_file)
        return True
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("register_self failed: %s", exc)
        return False
