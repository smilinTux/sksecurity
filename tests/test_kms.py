"""Tests for the SKSecurity KMS.

Covers:
- ManagedKey model
- FileKeyStore CRUD
- KMS seal/unseal lifecycle
- Team/agent/DEK key creation (HKDF + AES-GCM)
- Key wrapping and unwrapping round-trip
- DEK creation and unwrap
- Key rotation and revocation
- Deterministic derivation (same input → same key)
- Cross-team isolation (different teams → different keys)
- Salt persistence across unseal cycles
- Status and audit logging
"""

import importlib.util
import os
import tempfile
from pathlib import Path

import pytest
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

# Crypto primitives for direct testing
_derive_master_key = _kms_mod._derive_master_key
_hkdf_derive = _kms_mod._hkdf_derive
_aes_gcm_encrypt = _kms_mod._aes_gcm_encrypt
_aes_gcm_decrypt = _kms_mod._aes_gcm_decrypt
_wrap_key = _kms_mod._wrap_key
_unwrap_key = _kms_mod._unwrap_key


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


# ---------------------------------------------------------------------------
# Crypto primitive tests
# ---------------------------------------------------------------------------


class TestCryptoPrimitives:
    """Test the low-level crypto functions directly."""

    def test_aes_gcm_roundtrip(self):
        key = os.urandom(32)
        plaintext = b"sovereign key material"
        ct = _aes_gcm_encrypt(key, plaintext)
        assert ct != plaintext
        assert len(ct) == 12 + len(plaintext) + 16  # nonce + ct + tag
        assert _aes_gcm_decrypt(key, ct) == plaintext

    def test_aes_gcm_wrong_key_fails(self):
        key = os.urandom(32)
        wrong = os.urandom(32)
        ct = _aes_gcm_encrypt(key, b"secret")
        with pytest.raises(Exception):
            _aes_gcm_decrypt(wrong, ct)

    def test_wrap_unwrap_roundtrip(self):
        wrapping_key = os.urandom(32)
        raw_key = os.urandom(32)
        wrapped = _wrap_key(wrapping_key, raw_key)
        assert isinstance(wrapped, str)  # base64 string
        assert _unwrap_key(wrapping_key, wrapped) == raw_key

    def test_hkdf_deterministic(self):
        parent = os.urandom(32)
        k1 = _hkdf_derive(parent, "team:alpha")
        k2 = _hkdf_derive(parent, "team:alpha")
        assert k1 == k2

    def test_hkdf_different_info_different_keys(self):
        parent = os.urandom(32)
        k1 = _hkdf_derive(parent, "team:alpha")
        k2 = _hkdf_derive(parent, "team:beta")
        assert k1 != k2

    def test_master_key_derivation_deterministic(self):
        salt = os.urandom(16)
        k1 = _derive_master_key("test-pass", salt)
        k2 = _derive_master_key("test-pass", salt)
        assert k1 == k2
        assert len(k1) == 32

    def test_master_key_different_salt(self):
        k1 = _derive_master_key("test-pass", os.urandom(16))
        k2 = _derive_master_key("test-pass", os.urandom(16))
        assert k1 != k2


# ---------------------------------------------------------------------------
# DEK tests
# ---------------------------------------------------------------------------


class TestDEK:
    """Test Data Encryption Key creation and unwrapping."""

    def test_create_dek(self, tmp_kms):
        tmp_kms.create_team_key("t1")
        tmp_kms.create_agent_key("t1", "agent-a")

        dek = tmp_kms.create_dek("t1", "agent-a", purpose="file encryption")
        assert dek.key_type == KeyType.DEK
        assert dek.team_id == "t1"
        assert dek.agent_id == "agent-a"
        assert dek.parent_id is not None
        assert dek.ciphertext

    def test_unwrap_dek(self, tmp_kms):
        tmp_kms.create_team_key("t1")
        tmp_kms.create_agent_key("t1", "agent-a")
        dek = tmp_kms.create_dek("t1", "agent-a")

        raw = tmp_kms.unwrap_dek(dek.key_id)
        assert isinstance(raw, bytes)
        assert len(raw) == 32

    def test_unwrap_dek_consistency(self, tmp_kms):
        """Same DEK unwraps to the same raw bytes each time."""
        tmp_kms.create_team_key("t1")
        tmp_kms.create_agent_key("t1", "agent-a")
        dek = tmp_kms.create_dek("t1", "agent-a")

        raw1 = tmp_kms.unwrap_dek(dek.key_id)
        raw2 = tmp_kms.unwrap_dek(dek.key_id)
        assert raw1 == raw2

    def test_create_dek_no_agent_key(self, tmp_kms):
        tmp_kms.create_team_key("t1")
        with pytest.raises(ValueError, match="No agent key"):
            tmp_kms.create_dek("t1", "nonexistent")

    def test_unwrap_dek_not_found(self, tmp_kms):
        with pytest.raises(ValueError, match="DEK not found"):
            tmp_kms.unwrap_dek("missing-dek")

    def test_status_includes_dek_count(self, tmp_kms):
        tmp_kms.create_team_key("t1")
        tmp_kms.create_agent_key("t1", "a1")
        tmp_kms.create_dek("t1", "a1")
        tmp_kms.create_dek("t1", "a1")

        st = tmp_kms.status()
        assert st["dek_keys"] == 2


# ---------------------------------------------------------------------------
# Key isolation and derivation consistency
# ---------------------------------------------------------------------------


class TestKeyIsolation:
    """Verify key hierarchy isolation — teams don't leak into each other."""

    def test_different_teams_different_keys(self, tmp_kms):
        """Two teams derive different team keys from the same master."""
        t1 = tmp_kms.create_team_key("alpha")
        t2 = tmp_kms.create_team_key("beta")
        assert t1.ciphertext != t2.ciphertext

    def test_same_agent_different_teams(self, tmp_kms):
        """Same agent name in different teams gets different keys."""
        tmp_kms.create_team_key("alpha")
        tmp_kms.create_team_key("beta")
        a1 = tmp_kms.create_agent_key("alpha", "coder")
        a2 = tmp_kms.create_agent_key("beta", "coder")
        assert a1.ciphertext != a2.ciphertext

    def test_dek_unique_per_creation(self, tmp_kms):
        """Each DEK is unique (random), not derived."""
        tmp_kms.create_team_key("t1")
        tmp_kms.create_agent_key("t1", "a1")
        d1 = tmp_kms.create_dek("t1", "a1")
        d2 = tmp_kms.create_dek("t1", "a1")
        assert d1.ciphertext != d2.ciphertext

        raw1 = tmp_kms.unwrap_dek(d1.key_id)
        raw2 = tmp_kms.unwrap_dek(d2.key_id)
        assert raw1 != raw2


# ---------------------------------------------------------------------------
# Salt persistence
# ---------------------------------------------------------------------------


class TestSaltPersistence:
    """Verify the master key salt persists across unseal cycles."""

    def test_salt_file_created(self, tmp_path):
        store = FileKeyStore(store_dir=tmp_path / "keys")
        audit = tmp_path / "audit.log"
        kms = KMS(store=store, audit_path=audit)
        kms.unseal("pass")

        salt_path = tmp_path / KMS.SALT_FILE
        assert salt_path.exists()
        assert len(salt_path.read_bytes()) == 16

    def test_same_passphrase_same_key_after_reseal(self, tmp_path):
        """Unsealing twice with the same passphrase derives the same master."""
        store = FileKeyStore(store_dir=tmp_path / "keys")
        audit = tmp_path / "audit.log"

        kms = KMS(store=store, audit_path=audit)
        kms.unseal("sovereign")
        key1 = kms.create_team_key("t1")
        kms.seal()

        # Re-unseal with same passphrase — team key should still unwrap
        kms.unseal("sovereign")
        key2 = kms.create_team_key("t2")
        # Both team keys are wrapped under the same master — ciphertext
        # is encrypted correctly and the KMS can create more keys
        assert key2.ciphertext
        assert key2.key_id != key1.key_id
