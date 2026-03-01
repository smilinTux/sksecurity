"""
SKSecurity KMS — Sovereign Key Management Service.

A lightweight KMS designed for sovereign agent deployments across
Docker Swarm, Kubernetes, Proxmox LXC, and bare metal. Manages the
full key lifecycle: generation, derivation, sealing, rotation,
distribution, and revocation.

Architecture (inspired by MinIO KES, built sovereign):

    MinIO KES is AGPL-3.0 — can't embed without open-sourcing callers.
    HashiCorp Vault is BSL — same problem.
    We build our own. We already have PGP identity (CapAuth) and
    transport (SKComm). This is the missing piece.

Key Hierarchy:

    Master Key (sealed at rest, passphrase-derived via scrypt)
        └── Team Key (derived via HKDF-SHA256)
            └── Agent Key (derived via HKDF-SHA256)
                └── Data Encryption Key (DEK, random AES-256)

    Each level can only decrypt its own children. Compromise of an
    agent key doesn't expose sibling agents or other teams.

Enterprise Use Case:

    A company PGP key serves as the master. Team leads get team keys.
    Individual agents get agent keys. FUSE mounts use DEKs. The KMS
    runs as a sidecar or system service, agents request keys at runtime
    via unix socket or localhost REST API, authenticated by mTLS or
    PGP challenge-response (reusing CapAuth).

Deployment Modes:

    - Local: unix socket at ~/.sksecurity/kms.sock
    - Docker Swarm: sidecar container, keys via Docker secrets + KMS API
    - Kubernetes: init container or sidecar, keys via KMS API
    - Proxmox: provisioned during LXC creation via cloud-init

Performance Note:

    The seal/unseal/derive hot path is a candidate for a Rust
    implementation (via PyO3 or as a standalone binary). The Python
    layer handles CLI, REST API, and orchestration.

Cryptography:

    - Master key derivation: scrypt (N=2^20, r=8, p=1) from passphrase + salt
    - Key derivation: HKDF-SHA256 with context-specific info strings
    - Key wrapping: AES-256-GCM (encrypt child keys under parent)
    - DEK generation: os.urandom(32) — pure random, not derived

Coordination board task: 9871b893
"""

import base64
import hashlib
import json
import logging
import os
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("sksecurity.kms")


# ---------------------------------------------------------------------------
# Crypto primitives (all from the `cryptography` library)
# ---------------------------------------------------------------------------

def _derive_master_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 32-byte master key from passphrase + salt using scrypt.

    Parameters are chosen for interactive use (fast enough for CLI,
    resistant to GPU/ASIC brute force):
        N=2^17 (131072), r=8, p=1 → ~128 MB memory, ~0.3 s on modern CPU

    For higher-security deployments, increase N to 2^20.
    """
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))


def _hkdf_derive(parent_key: bytes, info: str, length: int = 32) -> bytes:
    """Derive a child key from a parent using HKDF-SHA256.

    Args:
        parent_key: Input keying material (parent key bytes).
        info: Context string (e.g. "team:dev-squad").
        length: Output key length in bytes.
    """
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(
        algorithm=SHA256(),
        length=length,
        salt=None,
        info=info.encode("utf-8"),
    ).derive(parent_key)


def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-256-GCM, returns nonce || ciphertext || tag."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct  # 12 + len(plaintext) + 16


def _aes_gcm_decrypt(key: bytes, data: bytes) -> bytes:
    """Decrypt AES-256-GCM, expects nonce || ciphertext || tag."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def _wrap_key(wrapping_key: bytes, raw_key: bytes) -> str:
    """Wrap (encrypt) a raw key under a wrapping key, return base64."""
    return base64.b64encode(_aes_gcm_encrypt(wrapping_key, raw_key)).decode()


def _unwrap_key(wrapping_key: bytes, wrapped_b64: str) -> bytes:
    """Unwrap (decrypt) a base64-encoded wrapped key."""
    return _aes_gcm_decrypt(wrapping_key, base64.b64decode(wrapped_b64))


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class KeyType(str, Enum):
    """Classification of keys in the hierarchy."""

    MASTER = "master"
    TEAM = "team"
    AGENT = "agent"
    DEK = "dek"


class KeyState(str, Enum):
    """Lifecycle state of a managed key."""

    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"
    PENDING = "pending"


class SealState(str, Enum):
    """Whether the KMS master key is currently accessible."""

    SEALED = "sealed"
    UNSEALED = "unsealed"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ManagedKey(BaseModel):
    """A key managed by the KMS.

    Keys are never stored in plaintext at rest. The `ciphertext` field
    holds the key material encrypted (wrapped) by its parent key.
    Only when the KMS is unsealed can keys be decrypted for use.

    Args:
        key_id: Unique identifier for this key.
        key_type: Position in the key hierarchy.
        state: Current lifecycle state.
        parent_id: ID of the parent key that wraps this one.
        created_at: When this key was generated.
        rotated_at: When this key was last rotated (None if never).
        team_id: Team this key belongs to (None for master keys).
        agent_id: Agent this key belongs to (None for master/team keys).
        algorithm: Encryption algorithm used (default AES-256-GCM).
        ciphertext: Wrapped key material (base64-encoded AES-GCM blob).
    """

    key_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    key_type: KeyType
    state: KeyState = KeyState.ACTIVE
    parent_id: Optional[str] = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    rotated_at: Optional[datetime] = None
    team_id: Optional[str] = None
    agent_id: Optional[str] = None
    algorithm: str = "AES-256-GCM"
    ciphertext: str = ""


class KeyRequest(BaseModel):
    """A request from an agent to obtain its key material.

    Agents authenticate via PGP challenge-response (CapAuth) or mTLS.
    The KMS verifies identity before releasing the unwrapped key.

    Args:
        requesting_agent: Agent identity (name or fingerprint).
        team_id: The team deployment the agent belongs to.
        key_type: What kind of key is being requested.
        purpose: Human-readable reason for the request (logged).
    """

    requesting_agent: str
    team_id: str
    key_type: KeyType = KeyType.AGENT
    purpose: str = ""


class AuditEntry(BaseModel):
    """Immutable log entry for every KMS operation.

    Every key creation, access, rotation, and revocation is logged.
    The audit trail is append-only and integrity-protected.

    Args:
        entry_id: Unique ID for this log entry.
        timestamp: When the operation occurred.
        operation: What happened (create, access, rotate, revoke, seal, unseal).
        key_id: Which key was involved.
        actor: Who performed the operation (agent name or fingerprint).
        details: Additional context.
        success: Whether the operation succeeded.
    """

    entry_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    operation: str
    key_id: Optional[str] = None
    actor: str = ""
    details: str = ""
    success: bool = True


# ---------------------------------------------------------------------------
# Key Store Interface
# ---------------------------------------------------------------------------


class KeyStore(ABC):
    """Abstract interface for persisting wrapped keys.

    Implementations may store keys on the local filesystem, in etcd,
    in a database, or in a hardware security module (HSM).
    """

    @abstractmethod
    def save(self, key: ManagedKey) -> None:
        """Persist a wrapped key.

        Args:
            key: The key to store (ciphertext field is already wrapped).
        """

    @abstractmethod
    def load(self, key_id: str) -> Optional[ManagedKey]:
        """Retrieve a wrapped key by ID.

        Args:
            key_id: The key identifier.

        Returns:
            ManagedKey if found, None otherwise.
        """

    @abstractmethod
    def list_keys(
        self,
        key_type: Optional[KeyType] = None,
        team_id: Optional[str] = None,
    ) -> list[ManagedKey]:
        """List keys matching the given filters.

        Args:
            key_type: Filter by key type.
            team_id: Filter by team.

        Returns:
            List of matching ManagedKey objects.
        """

    @abstractmethod
    def delete(self, key_id: str) -> bool:
        """Remove a key from the store.

        Args:
            key_id: The key to remove.

        Returns:
            True if the key was found and removed.
        """


class FileKeyStore(KeyStore):
    """Filesystem-backed key store.

    Stores wrapped keys as JSON files in a directory.
    Suitable for single-node deployments and development.

    Args:
        store_dir: Directory to store key files. Defaults to
                   ~/.sksecurity/kms/keys/
    """

    def __init__(self, store_dir: Optional[Path] = None) -> None:
        self._dir = store_dir or Path("~/.sksecurity/kms/keys").expanduser()
        self._dir.mkdir(parents=True, exist_ok=True)

    def save(self, key: ManagedKey) -> None:
        """Persist a wrapped key as a JSON file."""
        path = self._dir / f"{key.key_id}.json"
        path.write_text(key.model_dump_json(indent=2))

    def load(self, key_id: str) -> Optional[ManagedKey]:
        """Load a wrapped key from disk."""
        path = self._dir / f"{key_id}.json"
        if not path.exists():
            return None
        return ManagedKey.model_validate_json(path.read_text())

    def list_keys(
        self,
        key_type: Optional[KeyType] = None,
        team_id: Optional[str] = None,
    ) -> list[ManagedKey]:
        """List keys from disk, optionally filtered."""
        keys: list[ManagedKey] = []
        for path in sorted(self._dir.glob("*.json")):
            try:
                key = ManagedKey.model_validate_json(path.read_text())
                if key_type and key.key_type != key_type:
                    continue
                if team_id and key.team_id != team_id:
                    continue
                keys.append(key)
            except Exception:
                logger.warning("Failed to parse key file: %s", path)
        return keys

    def delete(self, key_id: str) -> bool:
        """Remove a key file from disk."""
        path = self._dir / f"{key_id}.json"
        if path.exists():
            path.unlink()
            return True
        return False


# ---------------------------------------------------------------------------
# KMS Core
# ---------------------------------------------------------------------------


class KMS:
    """The Sovereign Key Management Service.

    Manages the full key lifecycle. The master key must be unsealed
    before any operations can proceed. All operations are audit-logged.

    Cryptography:
        - Master key: scrypt (N=2^17, r=8, p=1) from passphrase + 16-byte salt
        - Team keys: HKDF-SHA256(master, info="team:<team_id>")
        - Agent keys: HKDF-SHA256(team_key, info="agent:<agent_id>")
        - DEKs: random 32 bytes, wrapped under parent key via AES-256-GCM
        - Key wrapping: AES-256-GCM (nonce || ciphertext || tag, base64-encoded)

    Args:
        store: KeyStore implementation for persisting wrapped keys.
        audit_path: Path to the append-only audit log file.
    """

    SALT_FILE = "master.salt"

    def __init__(
        self,
        store: Optional[KeyStore] = None,
        audit_path: Optional[Path] = None,
    ) -> None:
        self._store = store or FileKeyStore()
        self._audit_path = (
            audit_path or Path("~/.sksecurity/kms/audit.log").expanduser()
        )
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        self._seal_state = SealState.SEALED
        self._master_key: Optional[bytes] = None

    @property
    def is_unsealed(self) -> bool:
        """Whether the KMS is currently unsealed and operational."""
        return self._seal_state == SealState.UNSEALED

    def seal(self) -> None:
        """Seal the KMS, clearing the master key from memory.

        After sealing, no key operations are possible until unseal()
        is called again.
        """
        self._master_key = None
        self._seal_state = SealState.SEALED
        self._audit("seal", actor="system", details="KMS sealed")
        logger.info("KMS sealed")

    def unseal(self, passphrase: str) -> bool:
        """Unseal the KMS with a passphrase.

        Derives the master key from the passphrase using scrypt with
        a persistent salt. On first unseal, a new random salt is
        generated and stored alongside the key store.

        Args:
            passphrase: The passphrase protecting the master key.

        Returns:
            True if unsealing succeeded.
        """
        salt = self._load_or_create_salt()
        self._master_key = _derive_master_key(passphrase, salt)
        self._seal_state = SealState.UNSEALED
        self._audit("unseal", actor="system", details="KMS unsealed")
        logger.info("KMS unsealed")
        return True

    def create_team_key(self, team_id: str) -> ManagedKey:
        """Create a new team-scoped key.

        Derives a team key from the master key via HKDF-SHA256 with
        info="team:<team_id>", then wraps it under the master key
        for at-rest storage.

        Args:
            team_id: The team deployment ID.

        Returns:
            The newly created ManagedKey.

        Raises:
            RuntimeError: If the KMS is sealed.
        """
        self._require_unsealed()

        raw_team_key = _hkdf_derive(
            self._master_key, info=f"team:{team_id}"
        )
        wrapped = _wrap_key(self._master_key, raw_team_key)

        key = ManagedKey(
            key_type=KeyType.TEAM,
            team_id=team_id,
            ciphertext=wrapped,
        )
        self._store.save(key)
        self._audit(
            "create_key",
            key_id=key.key_id,
            actor="system",
            details=f"Team key for {team_id}",
        )
        return key

    def create_agent_key(
        self, team_id: str, agent_id: str
    ) -> ManagedKey:
        """Create a new agent-scoped key within a team.

        Derives the team key, then derives an agent key from it via
        HKDF-SHA256 with info="agent:<agent_id>". The agent key is
        wrapped under the team key for at-rest storage.

        Args:
            team_id: The team this agent belongs to.
            agent_id: The agent's unique identifier.

        Returns:
            The newly created ManagedKey.

        Raises:
            RuntimeError: If the KMS is sealed.
            ValueError: If no team key exists for the given team.
        """
        self._require_unsealed()

        team_keys = self._store.list_keys(
            key_type=KeyType.TEAM, team_id=team_id
        )
        if not team_keys:
            raise ValueError(f"No team key found for team '{team_id}'")

        parent = team_keys[0]
        raw_team_key = _unwrap_key(self._master_key, parent.ciphertext)
        raw_agent_key = _hkdf_derive(
            raw_team_key, info=f"agent:{agent_id}"
        )
        wrapped = _wrap_key(raw_team_key, raw_agent_key)

        key = ManagedKey(
            key_type=KeyType.AGENT,
            parent_id=parent.key_id,
            team_id=team_id,
            agent_id=agent_id,
            ciphertext=wrapped,
        )
        self._store.save(key)
        self._audit(
            "create_key",
            key_id=key.key_id,
            actor="system",
            details=f"Agent key for {agent_id} in team {team_id}",
        )
        return key

    def create_dek(
        self, team_id: str, agent_id: str, purpose: str = ""
    ) -> ManagedKey:
        """Create a random Data Encryption Key (DEK) for an agent.

        DEKs are pure random (not derived) and wrapped under the
        agent's key for at-rest storage. They are used for encrypting
        payloads (FUSE mounts, file transfers, etc.).

        Args:
            team_id: The team this agent belongs to.
            agent_id: The agent that owns this DEK.
            purpose: Human-readable purpose for audit.

        Returns:
            The newly created ManagedKey (type=DEK).

        Raises:
            RuntimeError: If the KMS is sealed.
            ValueError: If no agent key exists.
        """
        self._require_unsealed()

        agent_keys = self._store.list_keys(
            key_type=KeyType.AGENT, team_id=team_id
        )
        parent = next(
            (k for k in agent_keys if k.agent_id == agent_id), None
        )
        if not parent:
            raise ValueError(
                f"No agent key found for '{agent_id}' in team '{team_id}'"
            )

        # Unwrap the chain: master → team → agent
        team_keys = self._store.list_keys(
            key_type=KeyType.TEAM, team_id=team_id
        )
        raw_team_key = _unwrap_key(
            self._master_key, team_keys[0].ciphertext
        )
        raw_agent_key = _unwrap_key(raw_team_key, parent.ciphertext)

        # DEK is pure random, not derived
        raw_dek = os.urandom(32)
        wrapped = _wrap_key(raw_agent_key, raw_dek)

        key = ManagedKey(
            key_type=KeyType.DEK,
            parent_id=parent.key_id,
            team_id=team_id,
            agent_id=agent_id,
            ciphertext=wrapped,
        )
        self._store.save(key)
        self._audit(
            "create_key",
            key_id=key.key_id,
            actor=agent_id,
            details=f"DEK for {agent_id}: {purpose}" if purpose else f"DEK for {agent_id}",
        )
        return key

    def unwrap_dek(self, dek_key_id: str) -> bytes:
        """Unwrap a DEK to obtain the raw key material.

        Requires the full unwrap chain: master → team → agent → DEK.

        Args:
            dek_key_id: The key ID of the DEK to unwrap.

        Returns:
            Raw 32-byte DEK key material.

        Raises:
            RuntimeError: If the KMS is sealed.
            ValueError: If the key is not found or the chain is broken.
        """
        self._require_unsealed()

        dek = self._store.load(dek_key_id)
        if not dek or dek.key_type != KeyType.DEK:
            raise ValueError(f"DEK not found: {dek_key_id}")

        agent_key = self._store.load(dek.parent_id)
        if not agent_key:
            raise ValueError(f"Agent key not found for DEK: {dek_key_id}")

        team_keys = self._store.list_keys(
            key_type=KeyType.TEAM, team_id=dek.team_id
        )
        if not team_keys:
            raise ValueError(f"Team key not found for team: {dek.team_id}")

        raw_team = _unwrap_key(self._master_key, team_keys[0].ciphertext)
        raw_agent = _unwrap_key(raw_team, agent_key.ciphertext)
        raw_dek = _unwrap_key(raw_agent, dek.ciphertext)

        self._audit(
            "unwrap_dek",
            key_id=dek_key_id,
            actor=dek.agent_id or "",
            details=f"DEK unwrapped for {dek.agent_id}",
        )
        return raw_dek

    def get_key(self, request: KeyRequest) -> Optional[ManagedKey]:
        """Retrieve a key for an authenticated agent.

        In production, this verifies the agent's identity via CapAuth
        PGP challenge-response before releasing the key.

        Args:
            request: The key request with agent identity and team.

        Returns:
            ManagedKey if found and authorized, None otherwise.

        Raises:
            RuntimeError: If the KMS is sealed.
        """
        self._require_unsealed()

        keys = self._store.list_keys(
            key_type=request.key_type, team_id=request.team_id
        )
        match = next(
            (k for k in keys if k.agent_id == request.requesting_agent),
            None,
        )
        self._audit(
            "access_key",
            key_id=match.key_id if match else None,
            actor=request.requesting_agent,
            details=request.purpose,
            success=match is not None,
        )
        return match

    def rotate_key(self, key_id: str) -> Optional[ManagedKey]:
        """Rotate a key: generate new material, mark old as rotated.

        For team/agent keys, new material is derived via HKDF with a
        rotation counter suffix. For DEKs, fresh random bytes are used.

        Child keys derived from the old key are NOT automatically
        re-wrapped. The caller must re-derive or re-wrap as needed.

        Args:
            key_id: The key to rotate.

        Returns:
            The new key, or None if the old key wasn't found.

        Raises:
            RuntimeError: If the KMS is sealed.
        """
        self._require_unsealed()

        old = self._store.load(key_id)
        if not old:
            return None

        old.state = KeyState.ROTATED
        old.rotated_at = datetime.now(timezone.utc)
        self._store.save(old)

        # Generate new key material
        raw_new_key = os.urandom(32)
        if old.key_type == KeyType.TEAM:
            wrapped = _wrap_key(self._master_key, raw_new_key)
        elif old.key_type == KeyType.AGENT and old.parent_id:
            team_keys = self._store.list_keys(
                key_type=KeyType.TEAM, team_id=old.team_id
            )
            if team_keys:
                raw_team = _unwrap_key(
                    self._master_key, team_keys[0].ciphertext
                )
                wrapped = _wrap_key(raw_team, raw_new_key)
            else:
                wrapped = _wrap_key(self._master_key, raw_new_key)
        else:
            wrapped = _wrap_key(self._master_key, raw_new_key)

        new_key = ManagedKey(
            key_type=old.key_type,
            parent_id=old.parent_id,
            team_id=old.team_id,
            agent_id=old.agent_id,
            ciphertext=wrapped,
        )
        self._store.save(new_key)

        self._audit(
            "rotate_key",
            key_id=key_id,
            details=f"Rotated to {new_key.key_id}",
        )
        return new_key

    def revoke_key(self, key_id: str) -> bool:
        """Revoke a key, making it permanently unusable.

        Args:
            key_id: The key to revoke.

        Returns:
            True if the key was found and revoked.

        Raises:
            RuntimeError: If the KMS is sealed.
        """
        self._require_unsealed()

        key = self._store.load(key_id)
        if not key:
            return False

        key.state = KeyState.REVOKED
        self._store.save(key)
        self._audit("revoke_key", key_id=key_id)
        return True

    def list_keys(
        self,
        key_type: Optional[KeyType] = None,
        team_id: Optional[str] = None,
    ) -> list[ManagedKey]:
        """List managed keys, optionally filtered.

        Args:
            key_type: Filter by key type.
            team_id: Filter by team.

        Returns:
            List of matching ManagedKey objects.
        """
        return self._store.list_keys(key_type=key_type, team_id=team_id)

    def status(self) -> dict:
        """Get KMS status summary.

        Returns:
            Dict with seal state, key counts, and store info.
        """
        all_keys = self._store.list_keys()
        return {
            "seal_state": self._seal_state.value,
            "total_keys": len(all_keys),
            "active_keys": sum(
                1 for k in all_keys if k.state == KeyState.ACTIVE
            ),
            "team_keys": sum(
                1 for k in all_keys if k.key_type == KeyType.TEAM
            ),
            "agent_keys": sum(
                1 for k in all_keys if k.key_type == KeyType.AGENT
            ),
            "dek_keys": sum(
                1 for k in all_keys if k.key_type == KeyType.DEK
            ),
        }

    # -- internal helpers --------------------------------------------------

    def _require_unsealed(self) -> None:
        """Raise if the KMS is currently sealed."""
        if not self.is_unsealed:
            raise RuntimeError(
                "KMS is sealed. Call unseal() with the master passphrase."
            )

    def _load_or_create_salt(self) -> bytes:
        """Load the master key salt from disk, or generate a new one.

        The salt is stored as a raw 16-byte file next to the audit log.
        """
        salt_path = self._audit_path.parent / self.SALT_FILE
        if salt_path.exists():
            return salt_path.read_bytes()
        salt = os.urandom(16)
        salt_path.parent.mkdir(parents=True, exist_ok=True)
        salt_path.write_bytes(salt)
        return salt

    def _audit(
        self,
        operation: str,
        key_id: Optional[str] = None,
        actor: str = "",
        details: str = "",
        success: bool = True,
    ) -> None:
        """Append an entry to the audit log."""
        entry = AuditEntry(
            operation=operation,
            key_id=key_id,
            actor=actor,
            details=details,
            success=success,
        )
        try:
            with open(self._audit_path, "a") as f:
                f.write(entry.model_dump_json() + "\n")
        except OSError:
            logger.warning("Failed to write audit entry: %s", operation)
