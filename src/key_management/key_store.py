"""Encrypted, salted storage for hybrid wallet private keys."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import secrets
import tempfile
import time
from typing import Any, Dict, Mapping, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .recovery import SeedPhraseManager


class KeyStoreError(RuntimeError):
    """Raised when the encrypted key-store document is invalid."""


class SecureKeyStore:
    """Persist hybrid private keys using salted Scrypt and Fernet encryption.

    The file contains only encrypted key payloads and non-secret metadata.
    Each store has its own random salt, and writes use a restricted,
    fsync-backed temporary file followed by an atomic replacement.
    """

    FORMAT_VERSION = 2
    SALT_SIZE = 16
    SCRYPT_LENGTH = 32
    SCRYPT_N = 2**14
    SCRYPT_R = 8
    SCRYPT_P = 1

    def __init__(
        self,
        master_password: str,
        storage_file: str = "keys.encrypted.json",
    ) -> None:
        if not isinstance(master_password, str) or len(master_password) < 8:
            raise ValueError("Master password must be at least 8 characters")
        self.master_password = master_password
        self.storage_file = Path(storage_file)
        self._seed_manager = SeedPhraseManager()
        self._document = self._load_or_create_document()
        self._salt = self._decode_salt(self._document["salt"])
        self.derived_key = self._derive_key(self._salt, master_password)
        self.cipher_suite = Fernet(self.derived_key)

    def _load_or_create_document(self) -> dict[str, Any]:
        if not self.storage_file.exists():
            return self._new_document(secrets.token_bytes(self.SALT_SIZE))
        try:
            with self.storage_file.open("r", encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise KeyStoreError("Encrypted key-store file is unreadable") from exc
        if not isinstance(document, dict) or document.get("version") != self.FORMAT_VERSION:
            raise KeyStoreError("Unsupported or invalid key-store format")
        if not isinstance(document.get("keys"), dict):
            raise KeyStoreError("Encrypted key-store keys field is invalid")
        self._decode_salt(document.get("salt"))
        return document

    def _new_document(self, salt: bytes) -> dict[str, Any]:
        return {
            "version": self.FORMAT_VERSION,
            "kdf": {
                "name": "scrypt",
                "length": self.SCRYPT_LENGTH,
                "n": self.SCRYPT_N,
                "r": self.SCRYPT_R,
                "p": self.SCRYPT_P,
            },
            "salt": base64.urlsafe_b64encode(salt).decode("ascii"),
            "created_at": int(time.time()),
            "keys": {},
        }

    @staticmethod
    def _decode_salt(encoded: Any) -> bytes:
        if not isinstance(encoded, str):
            raise KeyStoreError("Encrypted key-store salt is missing")
        try:
            salt = base64.urlsafe_b64decode(encoded.encode("ascii"))
        except (ValueError, UnicodeError) as exc:
            raise KeyStoreError("Encrypted key-store salt is invalid") from exc
        if len(salt) != SecureKeyStore.SALT_SIZE:
            raise KeyStoreError("Encrypted key-store salt has the wrong size")
        return salt

    @classmethod
    def _derive_key(cls, salt: bytes, password: str) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=cls.SCRYPT_LENGTH,
            n=cls.SCRYPT_N,
            r=cls.SCRYPT_R,
            p=cls.SCRYPT_P,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    @classmethod
    def _build_cipher(cls, salt: bytes, password: str) -> Fernet:
        return Fernet(cls._derive_key(salt, password))

    def _read_current_document(self) -> dict[str, Any]:
        if not self.storage_file.exists():
            return self._document
        try:
            with self.storage_file.open("r", encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise KeyStoreError("Encrypted key-store file is unreadable") from exc
        if document.get("version") != self.FORMAT_VERSION or not isinstance(
            document.get("keys"), dict
        ):
            raise KeyStoreError("Encrypted key-store format is invalid")
        if self._decode_salt(document.get("salt")) != self._salt:
            raise KeyStoreError("Encrypted key-store salt changed unexpectedly")
        return document

    def _write_document(self, document: dict[str, Any]) -> None:
        parent = self.storage_file.parent
        parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{self.storage_file.name}.",
            dir=str(parent),
            text=True,
        )
        try:
            if os.name != "nt":
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.storage_file)
            if os.name != "nt":
                os.chmod(self.storage_file, 0o600)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    @staticmethod
    def _payload_dict(hybrid_key: Any) -> dict[str, Any]:
        if hasattr(hybrid_key, "to_dict"):
            hybrid_key = hybrid_key.to_dict()
        if not isinstance(hybrid_key, Mapping):
            raise TypeError("hybrid_key must be a mapping or serializable key object")
        payload = dict(hybrid_key)
        required = ("ecc_privkey", "pqc_privkey", "key_id")
        if any(field not in payload for field in required):
            raise ValueError(f"Key must contain: {list(required)}")
        if not isinstance(payload["key_id"], str) or not payload["key_id"]:
            raise ValueError("Key key_id must be a non-empty string")
        try:
            json.dumps(payload)
        except (TypeError, ValueError) as exc:
            raise ValueError("Hybrid key must contain JSON-serializable values") from exc
        return payload

    def store_hybrid_key(
        self,
        key_id: str,
        hybrid_key: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Encrypt and atomically store one hybrid private key."""
        try:
            if not isinstance(key_id, str) or not key_id:
                raise ValueError("key_id must be a non-empty string")
            payload = self._payload_dict(hybrid_key)
            if payload["key_id"] != key_id:
                raise ValueError("key_id does not match the hybrid key payload")
            document = self._read_current_document()
            encrypted = self.cipher_suite.encrypt(
                json.dumps(payload, sort_keys=True).encode("utf-8")
            ).decode("ascii")
            document["keys"][key_id] = {
                "encrypted": encrypted,
                "algorithm": payload.get(
                    "pqc_algorithm",
                    payload.get("algorithm", "ml-dsa+secp256k1"),
                ),
                "stored_at": int(time.time()),
                "metadata": dict(metadata or {}),
            }
            self._write_document(document)
            self._document = document
            return True
        except (OSError, TypeError, ValueError, KeyStoreError):
            return False

    def store_hybrid_keypair(
        self,
        public_key: Any,
        private_key: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Store a HybridWallet public/private pair in one encrypted payload."""
        if not hasattr(public_key, "to_dict") or not hasattr(private_key, "to_dict"):
            return False
        payload = private_key.to_dict()
        payload.update(
            {
                "ecc_pubkey": public_key.ecc_pubkey.hex(),
                "pqc_pubkey": public_key.pqc_pubkey.hex(),
                "created_at": public_key.created_at,
                "pqc_algorithm": public_key.pqc_algorithm,
            }
        )
        return self.store_hybrid_key(public_key.key_id, payload, metadata)

    def retrieve_hybrid_key(self, key_id: str) -> Optional[dict[str, Any]]:
        """Decrypt and return a stored key payload, or None if unavailable."""
        try:
            document = self._read_current_document()
            record = document["keys"].get(key_id)
            if not isinstance(record, dict):
                return None
            encrypted = record.get("encrypted")
            if not isinstance(encrypted, str):
                return None
            plaintext = self.cipher_suite.decrypt(encrypted.encode("ascii"))
            payload = json.loads(plaintext.decode("utf-8"))
            return payload if isinstance(payload, dict) else None
        except (InvalidToken, KeyError, TypeError, ValueError, KeyStoreError, OSError):
            return None

    def delete_key(self, key_id: str) -> bool:
        try:
            document = self._read_current_document()
            if key_id not in document["keys"]:
                return False
            del document["keys"][key_id]
            self._write_document(document)
            self._document = document
            return True
        except (OSError, KeyStoreError):
            return False

    def list_key_ids(self) -> list[str]:
        try:
            return list(self._read_current_document()["keys"].keys())
        except (KeyStoreError, OSError):
            return []

    def get_key_metadata(self, key_id: str) -> Optional[dict[str, Any]]:
        try:
            record = self._read_current_document()["keys"].get(key_id)
            if not isinstance(record, dict):
                return None
            return {
                "algorithm": record.get("algorithm"),
                "stored_at": record.get("stored_at"),
                "metadata": dict(record.get("metadata") or {}),
            }
        except (KeyStoreError, OSError, TypeError, ValueError):
            return None

    def rotate_key(self, old_key_id: str, new_hybrid_key: Any) -> bool:
        old_metadata = self.get_key_metadata(old_key_id)
        if old_metadata is None:
            return False
        try:
            new_key_id = (
                new_hybrid_key.key_id
                if hasattr(new_hybrid_key, "key_id")
                else new_hybrid_key.get("key_id")
            )
            metadata = {
                "rotated_from": old_key_id,
                "rotation_time": int(time.time()),
                "previous_metadata": old_metadata.get("metadata", {}),
            }
            return self.store_hybrid_key(new_key_id, new_hybrid_key, metadata)
        except (AttributeError, TypeError, ValueError):
            return False

    def export_public_keys(self, key_id: str) -> Optional[dict[str, Any]]:
        key_data = self.retrieve_hybrid_key(key_id)
        if not key_data:
            return None
        return {
            name: key_data[name]
            for name in (
                "key_id",
                "ecc_pubkey",
                "pqc_pubkey",
                "pqc_algorithm",
                "algorithm",
                "created_at",
            )
            if name in key_data
        }

    def generate_seed_phrase(
        self,
        key_id: Optional[str] = None,
        num_words: int = 12,
    ) -> str:
        """Generate a BIP39 phrase; optionally require an existing key ID.

        The phrase is returned to the caller and is never written to disk.
        Deriving a deterministic PQC key hierarchy from it is a separate
        protocol decision and is intentionally not implied by this method.
        """
        if key_id is not None and key_id not in self.list_key_ids():
            raise KeyError(f"Unknown hybrid key: {key_id}")
        return self._seed_manager.generate_wallet_seed(num_words)[0]

    def change_master_password(self, new_password: str) -> bool:
        if not isinstance(new_password, str) or len(new_password) < 8:
            return False
        try:
            old_document = self._read_current_document()
            decrypted = {}
            for key_id in old_document["keys"]:
                payload = self.retrieve_hybrid_key(key_id)
                if payload is None:
                    return False
                decrypted[key_id] = payload
            new_salt = secrets.token_bytes(self.SALT_SIZE)
            new_cipher = self._build_cipher(new_salt, new_password)
            new_document = self._new_document(new_salt)
            for key_id, payload in decrypted.items():
                record = old_document["keys"][key_id]
                new_document["keys"][key_id] = {
                    "encrypted": new_cipher.encrypt(
                        json.dumps(payload, sort_keys=True).encode("utf-8")
                    ).decode("ascii"),
                    "algorithm": record.get("algorithm", "ml-dsa+secp256k1"),
                    "stored_at": record.get("stored_at", int(time.time())),
                    "metadata": dict(record.get("metadata") or {}),
                }
            self._write_document(new_document)
            self.master_password = new_password
            self._salt = new_salt
            self.derived_key = self._derive_key(new_salt, new_password)
            self.cipher_suite = Fernet(self.derived_key)
            self._document = new_document
            return True
        except (OSError, KeyStoreError, TypeError, ValueError):
            return False

    def __repr__(self) -> str:
        return f"SecureKeyStore(file={self.storage_file}, num_keys={len(self.list_key_ids())})"