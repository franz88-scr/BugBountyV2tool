"""Credential encryption, rotation, and secure storage for ReconChain.

Uses Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256) with a
machine-derived key for at-rest credential protection.

Usage:
    from reconchain.credentials import CredentialStore
    store = CredentialStore("/path/to/state")
    store.save("api_key", "sk-abc123")
    key = store.load("api_key")
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from reconchain.utils import ensure, log

_FERNET_AVAILABLE = False
try:
    from cryptography.fernet import Fernet, InvalidToken
    _FERNET_AVAILABLE = True
except ImportError:
    Fernet = None  # type: ignore[assignment,misc]
    InvalidToken = Exception


@dataclass
class CredentialEntry:
    """A single stored credential with metadata."""
    name: str
    encrypted_value: str
    created_at: float = field(default_factory=time.time)
    rotated_at: Optional[float] = None
    rotation_count: int = 0
    expires_at: Optional[float] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "encrypted_value": self.encrypted_value,
            "created_at": self.created_at,
            "rotation_count": self.rotation_count,
            "tags": list(self.tags),
        }
        if self.rotated_at is not None:
            d["rotated_at"] = self.rotated_at
        if self.expires_at is not None:
            d["expires_at"] = self.expires_at
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CredentialEntry":
        return cls(
            name=d["name"],
            encrypted_value=d["encrypted_value"],
            created_at=d.get("created_at", 0.0),
            rotated_at=d.get("rotated_at"),
            rotation_count=d.get("rotation_count", 0),
            expires_at=d.get("expires_at"),
            tags=d.get("tags", []),
        )


def _derive_key() -> bytes:
    """Derive a Fernet key from machine-specific entropy.

    The key is not stored on disk — it's derived each time from a combination
    of hostname, user, and a salt stored in the state directory.
    """
    hostname = platform.node().encode()
    user = os.environ.get("USER", os.environ.get("LOGNAME", "root")).encode()
    raw = hostname + user
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()[:32])


class CredentialStore:
    """Encrypted credential storage with rotation support.

    Credentials are encrypted using Fernet (AES-128-CBC + HMAC-SHA256).
    The encryption key is derived from machine-specific entropy and is
    never stored on disk in plaintext.
    """

    def __init__(self, state_dir: Path, *, auto_load: bool = True) -> None:
        self._state_dir = Path(state_dir)
        self._cred_path = self._state_dir / ".credentials.enc"
        self._salt_path = self._state_dir / ".cred_salt"
        self._lock = threading.Lock()
        self._entries: Dict[str, CredentialEntry] = {}
        self._fernet: Any = None
        self._supported = _FERNET_AVAILABLE

        if auto_load:
            self._init_encryption()
            self._load()

    def _init_encryption(self) -> None:
        if not self._supported:
            return
        salt = self._load_or_create_salt()
        key_material = _derive_key() + salt
        fernet_key = base64.urlsafe_b64encode(hashlib.sha256(key_material).digest()[:32])
        self._fernet = Fernet(fernet_key)

    def _load_or_create_salt(self) -> bytes:
        if self._salt_path.exists():
            return self._salt_path.read_bytes()[:32]
        salt = secrets.token_bytes(32)
        import os as _os
        fd = _os.open(str(self._salt_path), _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL, 0o600)
        with _os.fdopen(fd, "wb") as f:
            f.write(salt)
        return salt

    def _encrypt(self, plaintext: str) -> str:
        if not self._supported or self._fernet is None:
            log("warn", "credential store: cryptography not available; storing credentials in plaintext")
            return plaintext
        return self._fernet.encrypt(plaintext.encode()).decode()

    def _decrypt(self, ciphertext: str) -> str:
        if not self._supported or self._fernet is None:
            return ciphertext
        try:
            return self._fernet.decrypt(ciphertext.encode()).decode()
        except InvalidToken:
            log("warn", f"credential store: failed to decrypt credential (invalid token)")
            return ""

    def _load(self) -> None:
        if not self._cred_path.exists():
            return
        try:
            raw = json.loads(self._cred_path.read_text(encoding="utf-8"))
            for entry_dict in raw.get("entries", []):
                entry = CredentialEntry.from_dict(entry_dict)
                self._entries[entry.name] = entry
        except Exception as e:
            log("warn", f"credential store: failed to load: {e}")

    def _save(self) -> None:
        ensure(self._cred_path)
        data = {
            "version": 1,
            "entries": [e.to_dict() for e in self._entries.values()],
        }
        fd, tmp = None, None
        import tempfile, os as _os
        fd, tmp = tempfile.mkstemp(dir=str(self._state_dir), suffix=".tmp")
        try:
            with _os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            _os.replace(tmp, str(self._cred_path))
        except Exception:
            if tmp:
                with _os.suppress(Exception):
                    _os.unlink(tmp)
            raise

    def save(self, name: str, value: str, *,
             tags: Optional[List[str]] = None,
             expires_in: Optional[float] = None) -> CredentialEntry:
        """Store an encrypted credential.

        Args:
            name: Unique credential identifier (e.g., "api_key", "ssh_pass").
            value: Plaintext credential value to encrypt.
            tags: Optional labels for grouping (e.g., ["proxy", "production"]).
            expires_in: Seconds until expiration (None = no expiry).

        Returns:
            The created CredentialEntry.
        """
        with self._lock:
            existing = self._entries.get(name)
            entry = CredentialEntry(
                name=name,
                encrypted_value=self._encrypt(value),
                created_at=existing.created_at if existing else time.time(),
                rotation_count=existing.rotation_count + 1 if existing else 0,
                rotated_at=time.time() if existing else None,
                expires_at=(time.time() + expires_in) if expires_in else None,
                tags=tags or (existing.tags if existing else []),
            )
            self._entries[name] = entry
            self._save()
            log("ok", f"credential saved: {name} (rotation #{entry.rotation_count})")
            return entry

    def load(self, name: str, *, check_expiry: bool = True) -> Optional[str]:
        """Load and decrypt a credential.

        Args:
            name: Credential identifier.
            check_expiry: If True, returns None for expired credentials.

        Returns:
            Decrypted credential string, or None if not found/expired.
        """
        with self._lock:
            entry = self._entries.get(name)
            if entry is None:
                return None
            if check_expiry and entry.expires_at and time.time() > entry.expires_at:
                log("warn", f"credential expired: {name}")
                return None
            return self._decrypt(entry.encrypted_value)

    def has(self, name: str) -> bool:
        with self._lock:
            return name in self._entries

    def rotate(self, name: str, new_value: str) -> Optional[CredentialEntry]:
        """Rotate a credential (alias for save with explicit semantics)."""
        if name not in self._entries:
            log("warn", f"cannot rotate non-existent credential: {name}")
            return None
        return self.save(name, new_value)

    def delete(self, name: str) -> bool:
        with self._lock:
            if name in self._entries:
                del self._entries[name]
                self._save()
                log("ok", f"credential deleted: {name}")
                return True
            return False

    def list_credentials(self, *, include_expired: bool = False) -> List[Dict[str, Any]]:
        """List all stored credential names and metadata (never values)."""
        with self._lock:
            result = []
            for entry in self._entries.values():
                if not include_expired and entry.expires_at and time.time() > entry.expires_at:
                    continue
                result.append({
                    "name": entry.name,
                    "created_at": entry.created_at,
                    "rotated_at": entry.rotated_at,
                    "rotation_count": entry.rotation_count,
                    "expired": bool(entry.expires_at and time.time() > entry.expires_at),
                    "tags": entry.tags,
                })
            return result

    def export_encrypted(self, target: Path) -> None:
        """Export all encrypted credentials to a portable file."""
        with self._lock:
            data = {
                "version": 1,
                "entries": [e.to_dict() for e in self._entries.values()],
            }
            ensure(target)
            target.write_text(json.dumps(data, indent=2))
            log("ok", f"exported {len(self._entries)} credentials → {target}")

    def import_encrypted(self, source: Path) -> int:
        """Import encrypted credentials from a file (merges, does not overwrite)."""
        if not source.exists():
            return 0
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
            count = 0
            for entry_dict in data.get("entries", []):
                entry = CredentialEntry.from_dict(entry_dict)
                if entry.name not in self._entries:
                    self._entries[entry.name] = entry
                    count += 1
            if count:
                self._save()
                log("ok", f"imported {count} new credentials from {source}")
            return count
        except Exception as e:
            log("warn", f"credential import failed: {e}")
            return 0
