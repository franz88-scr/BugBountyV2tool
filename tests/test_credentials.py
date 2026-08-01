"""Tests for the encrypted credential store."""

import time
from pathlib import Path

import pytest

from vulnforge.credentials import CredentialStore

try:
    import cryptography  # noqa: F401

    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

needs_crypto = pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography not installed")


@needs_crypto
class TestCredentialStore:
    def test_save_and_load(self, tmp_path: Path) -> None:
        store = CredentialStore(tmp_path)
        store.save("api_key", "sk-abc123")
        assert store.load("api_key") == "sk-abc123"
        assert store.has("api_key")

    def test_save_rotates_without_losing_identity(self, tmp_path: Path) -> None:
        store = CredentialStore(tmp_path)
        store.save("k", "v1")
        store.save("k", "v2")
        assert store.load("k") == "v2"
        entry = store._entries["k"]
        assert entry.rotation_count == 1
        assert entry.rotated_at is not None

    def test_expiry(self, tmp_path: Path) -> None:
        store = CredentialStore(tmp_path)
        store.save("k", "v", expires_in=0.01)
        time.sleep(0.05)
        assert store.load("k", check_expiry=True) is None

    def test_delete(self, tmp_path: Path) -> None:
        store = CredentialStore(tmp_path)
        store.save("k", "v")
        assert store.delete("k") is True
        assert store.has("k") is False
        assert store.delete("k") is False

    def test_list(self, tmp_path: Path) -> None:
        store = CredentialStore(tmp_path)
        store.save("a", "1")
        store.save("b", "2")
        names = {c["name"] for c in store.list_credentials()}
        assert names == {"a", "b"}

    def test_export_import_same_store(self, tmp_path: Path, tmp_path_factory: pytest.TempPathFactory) -> None:
        store = CredentialStore(tmp_path)
        store.save("api_key", "sk-xyz")
        target = tmp_path_factory.mktemp("export") / "creds.enc"
        store.export_encrypted(target)
        assert target.exists()

        # Restore into a store at the same path (same salt) after a wipe
        store._entries.clear()
        count = store.import_encrypted(target)
        assert count == 1
        assert store.load("api_key") == "sk-xyz"


class TestUnsupportedCrypto:
    def test_save_raises_runtime_error_without_crypto(self, tmp_path: Path) -> None:
        store = CredentialStore(tmp_path)
        store._supported = False
        store._fernet = None
        with pytest.raises(RuntimeError):
            store.save("k", "v")

    def test_load_raises_runtime_error_without_crypto(self, tmp_path: Path) -> None:
        from vulnforge.credentials import CredentialEntry

        store = CredentialStore(tmp_path)
        store._supported = False
        store._fernet = None
        store._entries["k"] = CredentialEntry(
            name="k",
            encrypted_value="some-ciphertext",
            created_at=time.time(),
        )
        with pytest.raises(RuntimeError):
            store.load("k")
