"""The suite must never write outside its tmp dirs."""

from pathlib import Path

from . import conftest


def test_home_is_a_tmp_dir(tmp_path):
    home = Path.home()
    assert str(home).startswith(str(tmp_path))
    assert home != conftest.REAL_HOME


def test_skcapstone_home_and_standalone_set(tmp_path):
    import os

    assert os.environ["SK_STANDALONE"] == "1"
    assert os.environ["SKCAPSTONE_HOME"].startswith(str(tmp_path))


def test_integration_is_inert_under_isolation(monkeypatch):
    """Even with a live-looking SDK, SK_STANDALONE keeps integration off, and
    nothing in the real registry is touched."""
    from sksecurity import integration

    class Boom:
        def __getattr__(self, name):
            raise AssertionError(f"skcapstone sdk.{name} must not be called in tests")

        def is_available(self):
            return True

    monkeypatch.setattr(integration, "_sdk", Boom())
    assert integration.is_present() is False
    assert integration.alert("t", {"a": 1}, level="info") is False


def test_real_registry_untouched():
    reg = conftest.REAL_REGISTRY
    if conftest.REAL_REGISTRY_MTIME is None:
        assert not reg.exists()
    else:
        assert reg.stat().st_mtime_ns == conftest.REAL_REGISTRY_MTIME
