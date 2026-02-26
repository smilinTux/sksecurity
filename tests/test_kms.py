"""Tests for the SKSecurity KMS stub."""

import tempfile
from pathlib import Path

import pytest

import importlib.util
import sys
from pathlib import Path

# Reason: sksecurity.__init__ imports flask-dependent dashboard module;
# load kms.py directly to avoid pulling in optional dependencies
_kms_path = Path(__file__).resolve().parent.parent / "sksecurity" / "kms.py"
_spec = importlib.util.spec_from_file_location("sksecurity_kms", _kms_path)
_kms_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_kms_mod)

FileKeyStore = _kms_mod.FileKeyStore
KeyRequest = _kms_mod.KeyRequest
KeyState = _kms_mod.KeyState
KeyType = _kms_mod.KeyType
KMS = _kms_mod.KMS
ManagedKey = _kms_mod.ManagedKey
SealState = _kms_mod.SealState


@pytest.fixture
def tmp_kms(tmp_path):
    """Create a KMS instance with a temp directory for keys and audit."""
    store = FileKeyStore(store_dir=tmp_path / "keys")
    audit = tmp_path / "audit.log"
    kms = KMS(store=store, audit_path=audit)
    kms.unseal("test-passphrase")
    return kms


class TestManagedKey:
    """Test ManagedKey model."""

    def test_defaults(self):
        key = ManagedKey(key_type=KeyType.MASTER)
        assert key.key_type == KeyType.MASTER
        assert key.state == KeyState.ACTIVE
        assert key.key_id
        assert len(key.key_id) == 16

    def test_team_key_fields(self):
        key = ManagedKey(key_type=KeyType.TEAM, team_id="dev-squad")
        assert key.team_id == "dev-squad"
        assert key.agent_id is None


class TestFileKeyStore:
    """Test filesystem-backed key store."""

    def test_save_and_load(self, tmp_path):
        store = FileKeyStore(store_dir=tmp_path)
        key = ManagedKey(key_type=KeyType.TEAM, team_id="t1", ciphertext="abc")
        store.save(key)

        loaded = store.load(key.key_id)
        assert loaded is not None
        assert loaded.key_id == key.key_id
        assert loaded.ciphertext == "abc"

    def test_load_missing(self, tmp_path):
        store = FileKeyStore(store_dir=tmp_path)
        assert store.load("nonexistent") is None

    def test_list_filtered(self, tmp_path):
        store = FileKeyStore(store_dir=tmp_path)
        store.save(ManagedKey(key_type=KeyType.TEAM, team_id="a"))
        store.save(ManagedKey(key_type=KeyType.TEAM, team_id="b"))
        store.save(ManagedKey(key_type=KeyType.AGENT, team_id="a"))

        assert len(store.list_keys()) == 3
        assert len(store.list_keys(key_type=KeyType.TEAM)) == 2
        assert len(store.list_keys(team_id="a")) == 2
        assert len(store.list_keys(key_type=KeyType.AGENT, team_id="a")) == 1

    def test_delete(self, tmp_path):
        store = FileKeyStore(store_dir=tmp_path)
        key = ManagedKey(key_type=KeyType.DEK)
        store.save(key)
        assert store.delete(key.key_id)
        assert store.load(key.key_id) is None
        assert not store.delete("already-gone")


class TestKMS:
    """Test the KMS core."""

    def test_starts_sealed(self, tmp_path):
        kms = KMS(store=FileKeyStore(tmp_path))
        assert not kms.is_unsealed
        with pytest.raises(RuntimeError, match="sealed"):
            kms.create_team_key("team1")

    def test_unseal_and_seal(self, tmp_path):
        kms = KMS(store=FileKeyStore(tmp_path))
        assert kms.unseal("pass")
        assert kms.is_unsealed
        kms.seal()
        assert not kms.is_unsealed

    def test_create_team_key(self, tmp_kms):
        key = tmp_kms.create_team_key("dev-squad")
        assert key.key_type == KeyType.TEAM
        assert key.team_id == "dev-squad"
        assert key.state == KeyState.ACTIVE
        assert key.ciphertext

    def test_create_agent_key(self, tmp_kms):
        tmp_kms.create_team_key("t1")
        agent_key = tmp_kms.create_agent_key("t1", "coder-01")
        assert agent_key.key_type == KeyType.AGENT
        assert agent_key.team_id == "t1"
        assert agent_key.agent_id == "coder-01"
        assert agent_key.parent_id is not None

    def test_create_agent_key_no_team(self, tmp_kms):
        with pytest.raises(ValueError, match="No team key"):
            tmp_kms.create_agent_key("nonexistent", "agent1")

    def test_get_key(self, tmp_kms):
        tmp_kms.create_team_key("t1")
        tmp_kms.create_agent_key("t1", "agent-x")

        req = KeyRequest(
            requesting_agent="agent-x",
            team_id="t1",
            key_type=KeyType.AGENT,
            purpose="testing",
        )
        result = tmp_kms.get_key(req)
        assert result is not None
        assert result.agent_id == "agent-x"

    def test_get_key_not_found(self, tmp_kms):
        req = KeyRequest(
            requesting_agent="ghost",
            team_id="t1",
        )
        assert tmp_kms.get_key(req) is None

    def test_rotate_key(self, tmp_kms):
        key = tmp_kms.create_team_key("t1")
        new_key = tmp_kms.rotate_key(key.key_id)
        assert new_key is not None
        assert new_key.key_id != key.key_id

        old = tmp_kms._store.load(key.key_id)
        assert old.state == KeyState.ROTATED

    def test_rotate_missing(self, tmp_kms):
        assert tmp_kms.rotate_key("missing") is None

    def test_revoke_key(self, tmp_kms):
        key = tmp_kms.create_team_key("t1")
        assert tmp_kms.revoke_key(key.key_id)
        revoked = tmp_kms._store.load(key.key_id)
        assert revoked.state == KeyState.REVOKED

    def test_revoke_missing(self, tmp_kms):
        assert not tmp_kms.revoke_key("missing")

    def test_status(self, tmp_kms):
        tmp_kms.create_team_key("t1")
        tmp_kms.create_agent_key("t1", "a1")
        tmp_kms.create_agent_key("t1", "a2")

        st = tmp_kms.status()
        assert st["seal_state"] == "unsealed"
        assert st["total_keys"] == 3
        assert st["team_keys"] == 1
        assert st["agent_keys"] == 2

    def test_audit_log_written(self, tmp_path):
        store = FileKeyStore(tmp_path / "keys")
        audit = tmp_path / "audit.log"
        kms = KMS(store=store, audit_path=audit)
        kms.unseal("pass")
        kms.create_team_key("t1")
        kms.seal()

        log_text = audit.read_text()
        assert "unseal" in log_text
        assert "create_key" in log_text
        assert "seal" in log_text
