"""Secure secp256k1 ECDSA wrapper used by the hybrid wallet."""

from __future__ import annotations

import hashlib
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


class ECDSAModule:
    """Bitcoin-compatible ECDSA signing and verification on secp256k1.

    The public API accepts either an arbitrary message or a 32-byte SHA-256
    digest. A 32-byte value is treated as an already-hashed message for
    compatibility with the existing transaction integration.
    """

    curve_name = "secp256k1"
    key_size = 32
    public_key_size_compressed = 33
    public_key_size_uncompressed = 65

    def __init__(self) -> None:
        self.curve = ec.SECP256K1()

    @staticmethod
    def _message_digest(message: bytes) -> bytes:
        if not isinstance(message, (bytes, bytearray, memoryview)):
            raise TypeError("message must be bytes-like")
        message = bytes(message)
        return message if len(message) == 32 else hashlib.sha256(message).digest()

    @staticmethod
    def _private_key_object(private_key: bytes) -> ec.EllipticCurvePrivateKey:
        if not isinstance(private_key, (bytes, bytearray, memoryview)):
            raise TypeError("private_key must be bytes-like")
        private_key = bytes(private_key)
        if len(private_key) != 32:
            raise ValueError("Invalid private key")
        private_key_int = int.from_bytes(private_key, "big")
        if not 0 < private_key_int < ECDSAModule._curve_order():
            raise ValueError("Invalid private key")
        return ec.derive_private_key(private_key_int, ec.SECP256K1())

    @staticmethod
    def _curve_order() -> int:
        return 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Return ``(private_key, compressed_public_key)``."""
        try:
            private_key = ec.generate_private_key(self.curve)
            private_bytes = private_key.private_numbers().private_value.to_bytes(32, "big")
            public_bytes = private_key.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.CompressedPoint,
            )
            return private_bytes, public_bytes
        except Exception as exc:
            raise RuntimeError(f"ECDSA keypair generation failed: {exc}") from exc

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Sign a message and return a DER-encoded ECDSA signature."""
        digest = self._message_digest(message)
        key = self._private_key_object(private_key)
        try:
            return key.sign(
                digest,
                ec.ECDSA(utils.Prehashed(hashes.SHA256())),
            )
        except Exception as exc:
            raise RuntimeError(f"ECDSA signing failed: {exc}") from exc

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Return whether a DER-encoded signature is valid for the public key."""
        try:
            digest = self._message_digest(message)
            if not isinstance(signature, (bytes, bytearray, memoryview)):
                return False
            if not isinstance(public_key, (bytes, bytearray, memoryview)):
                return False
            public_key = bytes(public_key)
            if len(public_key) not in (
                self.public_key_size_compressed,
                self.public_key_size_uncompressed,
            ):
                return False
            key = ec.EllipticCurvePublicKey.from_encoded_point(self.curve, public_key)
            key.verify(
                bytes(signature),
                digest,
                ec.ECDSA(utils.Prehashed(hashes.SHA256())),
            )
            return True
        except Exception:
            return False

    def _validate_private_key(self, private_key: bytes) -> bool:
        """Return whether a private key is a valid secp256k1 scalar."""
        try:
            self._private_key_object(private_key)
            return True
        except (TypeError, ValueError):
            return False

    def _derive_public_key(self, private_key: bytes) -> bytes:
        """Derive a compressed public key from a private key."""
        return self._private_key_object(private_key).public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        )