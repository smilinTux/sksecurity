"""Resolve the package version.

Lives in its own module rather than inline in ``__init__`` because ``__version__``
has to be assigned before the submodule imports there, and a function definition
ahead of those imports trips E402 on every one of them. A dunder assignment is
allowed in that position; a ``def`` is not.

The version used to be hardcoded in three places at once (pyproject.toml,
``__init__`` and setup.py) and they drifted apart, so three tagged releases all
rebuilt an already-published version and PyPI rejected each as a duplicate. The
git tag is the single source of truth now.
"""

from __future__ import annotations


def detect_version() -> str:
    """Installed version, else the build-time one, else an obvious fallback.

    Ordered by trustworthiness. The fallback is deliberately not a plausible
    number: a wrong-but-believable version is what caused the original outage,
    so this one is meant to look broken on sight.
    """
    try:
        from importlib.metadata import version

        return version("sksecurity")
    except Exception:  # not installed, or running straight from a source tree
        pass
    try:
        from ._version import version as scm_version  # written by setuptools-scm

        return scm_version
    except Exception:
        return "0.0.0+unknown"
