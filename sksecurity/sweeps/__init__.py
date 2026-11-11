"""Sweep registry. Each sweep is a module here exposing

    NAME: str
    HELP: str
    def run(**options) -> list[Finding]

and is listed in SWEEPS. Sweeps are report-only (see sksecurity.findings).
"""

from __future__ import annotations

import importlib
from typing import Callable, Dict, List

from ..findings import Finding

#: sweep name -> module path. Add one line per sweep.
SWEEPS: Dict[str, str] = {
    "deps": "sksecurity.sweeps.deps",
}


def get(name: str) -> Callable[..., List[Finding]]:
    if name not in SWEEPS:
        raise KeyError(f"unknown sweep {name!r}; known: {sorted(SWEEPS)}")
    return importlib.import_module(SWEEPS[name]).run
