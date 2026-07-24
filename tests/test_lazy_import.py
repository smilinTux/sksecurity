"""Tests that the top-level ``import sksecurity`` does not require Flask.

Flask (and flask_cors) are optional dependencies needed only for the web
dashboard. Pure KMS / scanner / secret-guard use must not pull them in.
The dashboard module keeps its Flask imports inside ``DashboardServer.__init__``
so the package imports cleanly when Flask is absent, and the dashboard still
raises a clear ImportError only when someone actually tries to construct it.

We simulate "Flask absent" with a meta-path finder that blocks flask /
flask_cors, and run the check in a fresh subprocess so no already-imported
Flask (or already-imported sksecurity) can mask the result.
"""

import subprocess
import sys
import textwrap


# Code executed in a clean interpreter with flask/flask_cors blocked.
_CHILD = textwrap.dedent(
    """
    import sys
    import importlib.abc


    class _BlockFlask(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if name == "flask" or name.startswith("flask.") or name == "flask_cors":
                raise ImportError("flask blocked for test: " + name)
            return None


    sys.meta_path.insert(0, _BlockFlask())

    # Top-level import must succeed without Flask installed/available.
    import sksecurity

    assert not any(
        m == "flask" or m.startswith("flask.") or m == "flask_cors"
        for m in sys.modules
    ), "importing sksecurity must not import Flask"

    # Public dashboard symbols are still exported (as class objects) ...
    from sksecurity import DashboardServer, SecurityDashboard

    # ... but actually constructing the dashboard fails loudly without Flask.
    try:
        DashboardServer()
    except ImportError:
        pass
    else:  # pragma: no cover - only hit on regression
        raise AssertionError("DashboardServer() should raise ImportError when Flask is absent")

    print("OK")
    """
)


def test_import_sksecurity_without_flask():
    """`import sksecurity` succeeds and does not import Flask."""
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        "import sksecurity failed with Flask blocked:\n"
        f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    assert proc.stdout.strip().endswith("OK"), proc.stdout
