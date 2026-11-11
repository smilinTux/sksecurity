"""
SKSecurity: secret guard, honest-claims gate, input screening and
post-quantum posture reports for the SK agent estate.

Modules:
    secret_guard    credential leak detection (``sksecurity guard``)
    honest_claims   forbidden-overclaim gate (``sksecurity claims``)
    email_screener  text heuristics for phishing / injection (``sksecurity screen``)
    pqc_report, pqc_posture, pqc_stacks   PQC self-report (``sksecurity pqc-*``)
    kms             HKDF + AES-GCM key-wrapping KMS (used by skcapstone)
    integration     optional sk-alert publishing when skcapstone is present
"""

from ._ver import detect_version

__version__ = detect_version()
__author__ = "smilinTux Team"
__license__ = "GPL-3.0-or-later"
__description__ = "Secret guard, honest-claims gate, input screening and PQC posture for AI agent estates"

from .email_screener import EmailScreener, ScreeningResult, Verdict, ThreatCategory
from .secret_guard import SecretGuard, GuardResult, SecretFinding

__all__ = [
    "EmailScreener",
    "ScreeningResult",
    "Verdict",
    "ThreatCategory",
    "SecretGuard",
    "GuardResult",
    "SecretFinding",
    "__version__",
    "__author__",
    "__license__",
    "__description__",
]
