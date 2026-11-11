"""The one finding type every sweep emits.

Contract (docs/EVALUATION-2026-11.md, steps 2 to 5):

- A sweep NEVER stores, logs or prints a secret value. It records where the
  problem is (``location``), what class it is (``klass``), and a salted
  fingerprint of the value so the same leak dedups across runs and nodes.
- ``fingerprint`` is the identity of a finding. The ITIL reporter keys
  incidents on it, so it must be stable across runs: build it with
  :func:`make_fingerprint` from stable parts only (never a timestamp).
- Sweeps are report-only. Nothing in a sweep moves, deletes or chmods a file.
"""

from __future__ import annotations

import hashlib
import os
import socket
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional

SEVERITIES = ("critical", "high", "medium", "low")

#: Salt for value fingerprints. Per estate, not secret in itself; it only
#: stops a fingerprint from being a plain unsalted hash of a short secret.
_SALT_ENV = "SKSECURITY_FINGERPRINT_SALT"
_DEFAULT_SALT = "sksecurity-v2"


def value_digest(value: str) -> str:
    """Salted SHA-256 of a secret value, truncated. The value is not kept."""
    salt = os.environ.get(_SALT_ENV, _DEFAULT_SALT)
    return hashlib.sha256(f"{salt}\0{value}".encode()).hexdigest()[:16]


def make_fingerprint(sweep: str, klass: str, *parts: str) -> str:
    """Stable id of a finding: sweep + class + stable parts (path, rule, digest)."""
    raw = "\0".join((sweep, klass, *parts))
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


@dataclass
class Finding:
    sweep: str  # "fs", "deps", "mail"
    klass: str  # e.g. "secret.git-remote-credential", "perm.world-readable", "dep.vuln"
    severity: str  # one of SEVERITIES
    location: str  # path[:line], package==version, or mail message id; never a value
    summary: str  # one line, human readable, no secret material
    fingerprint: str
    rule: str = ""
    kedb: Optional[str] = None  # matching KEDB id, e.g. "ke-leak-github-pat-dvre"
    remediation: str = ""
    host: str = field(default_factory=socket.gethostname)
    details: Dict[str, Any] = field(default_factory=dict)  # no secret values

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity!r}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
