"""Test isolation: no test may touch the real HOME or the real ~/.skcapstone.

History: running this suite with the real HOME once rewrote
~/.skcapstone/registry/sksecurity.json, because a monitor test called
register_self() and ensure_schedule() against the live skcapstone SDK.

Two layers:

1. Module level (runs at collection, before any test module imports the
   package): HOME and SKCAPSTONE_HOME point at a throwaway directory and
   SK_STANDALONE=1 disables the skcapstone integration. This covers code that
   resolves Path.home() at import time.
2. Autouse function fixture: a fresh tmp HOME per test.
"""

import os
import tempfile
from pathlib import Path

import pytest

#: Where the real HOME was, captured before we replace it (used by the
#: isolation test to prove the real registry was not touched).
REAL_HOME = Path(os.environ.get("HOME", "~")).expanduser()
REAL_REGISTRY = REAL_HOME / ".skcapstone" / "registry" / "sksecurity.json"
REAL_REGISTRY_MTIME = REAL_REGISTRY.stat().st_mtime_ns if REAL_REGISTRY.exists() else None

def _link_liboqs(home: Path) -> None:
    """`import oqs` tries to git clone and build liboqs under HOME when it is
    missing, which hangs a test run for minutes. If the real HOME has a liboqs
    install, expose it read-only in the fake HOME."""
    src = REAL_HOME / "_oqs"
    if src.is_dir() and not (home / "_oqs").exists():
        try:
            (home / "_oqs").symlink_to(src)
        except OSError:
            pass


_SESSION_HOME = tempfile.mkdtemp(prefix="sksecurity-test-home-")
_link_liboqs(Path(_SESSION_HOME))
os.environ["HOME"] = _SESSION_HOME
os.environ["SKCAPSTONE_HOME"] = str(Path(_SESSION_HOME) / ".skcapstone")
os.environ["SK_STANDALONE"] = "1"


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    _link_liboqs(home)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SKCAPSTONE_HOME", str(home / ".skcapstone"))
    monkeypatch.setenv("SK_STANDALONE", "1")
    yield home
