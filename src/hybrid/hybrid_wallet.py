"""Hybrid secp256k1 and ML-DSA wallet signing.

The hybrid signature format is deliberately small and versioned:

    [version: 1][ecc_signature_length: 2][ecc_signature]
    [pqc_signature_length: 2][pqc_signature]

Both signatures cover the exact same transaction bytes. Verification is
strict: malformed encodings, unknown versions, or either invalid signature
cause the complete hybrid signature to be rejected.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
import time
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from ..crypto.ecdsa_module import ECDSAModule
from ..pqc.core import DilithiumSigner


SIGNATURE_VERSION = 1
_SIGNATURE_HEADER = struct.Struct(">B H")
_LENGTH_FIELD_SIZE = 2


def _as_bytes(value: Any, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    value = bytes(value)
    if not value:
        raise ValueError(f"{name} must not be empty")
    return value


def _decode_hex_field(data: Mapping[str, Any], name: str) -> bytes:
    value = data.get(name)
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a hexadecimal string")
    try:
        return _as_bytes(bytes.fromhex(value), name)
    except ValueError as exc:
        raise ValueError(f"{name} must be valid hexadecimal") from exc


@dataclass(frozen=True)
class HybridPublicKey:
    """Public half of a hybrid keypair."""

    ecc_pubkey: bytes
    pqc_pubkey: bytes
    key_id: str
    created_at: int
    pqc_algorithm: str = "ML-DSA-65"

    def __post_init__(self) -> None:
        _as_bytes(self.ecc_pubkey, "ecc_pubkey")
        _as_bytes(self.pqc_pubkey, "pqc_pubkey")
        if len(self.ecc_pubkey) not in (33, 65):
            raise ValueError("ecc_pubkey must be a compressed or uncompressed secp256k1 key")
        if not self.key_id:
            raise ValueError("key_id must not be empty")
        if not isinstance(self.created_at, int) or self.created_at < 0:
            raise ValueError("created_at must be a non-negative integer")
        if not self.pqc_algorithm:
            raise ValueError("pqc_algorithm must not be empty")

    def to_dict(self) -> dict[str, Any]:
        """Serialize public material without exposing private keys."""
        return {
            "version": 1,
            "ecc_pubkey": bytes(self.ecc_pubkey).hex(),
            "pqc_pubkey": bytes(self.pqc_pubkey).hex(),
            "key_id": self.key_id,
            "created_at": self.created_at,
            "pqc_algorithm": self.pqc_algorithm,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HybridPublicKey":
        return cls(
            ecc_pubkey=_decode_hex_field(data, "ecc_pubkey"),
            pqc_pubkey=_decode_hex_field(data, "pqc_pubkey"),
            key_id=str(data.get("key_id", "")),
            created_at=data.get("created_at", -1),
            pqc_algorithm=str(data.get("pqc_algorithm", "ML-DSA-65")),
        )


@dataclass(frozen=True)
class HybridPrivateKey:
    """Private half of a hybrid keypair.

    Callers should pass this object to an encrypted key store rather than
    serializing it to an unprotected file.
    """

    ecc_privkey: bytes
    pqc_privkey: bytes
    key_id: str
    created_at: int
    pqc_algorithm: str = "ML-DSA-65"

    def __post_init__(self) -> None:
        _as_bytes(self.ecc_privkey, "ecc_privkey")
        _as_bytes(self.pqc_privkey, "pqc_privkey")
        if len(self.ecc_privkey) != 32:
            raise ValueError("ecc_privkey must be 32 bytes")
        if not self.key_id:
            raise ValueError("key_id must not be empty")
        if not isinstance(self.created_at, int) or self.created_at < 0:
            raise ValueError("created_at must be a non-negative integer")
        if not self.pqc_algorithm:
            raise ValueError("pqc_algorithm must not be empty")

    def to_dict(self) -> dict[str, Any]:
        """Serialize private material for an encrypted key store."""
        return {
            "version": 1,
            "ecc_privkey": bytes(self.ecc_privkey).hex(),
            "pqc_privkey": bytes(self.pqc_privkey).hex(),
            "key_id": self.key_id,
            "created_at": self.created_at,
            "pqc_algorithm": self.pqc_algorithm,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HybridPrivateKey":
        return cls(
            ecc_privkey=_decode_hex_field(data, "ecc_privkey"),
            pqc_privkey=_decode_hex_field(data, "pqc_privkey"),
            key_id=str(data.get("key_id", "")),
            created_at=data.get("created_at", -1),
            pqc_algorithm=str(data.get("pqc_algorithm", "ML-DSA-65")),
        )


@dataclass(frozen=True)
class HybridSignature:
    """Decoded versioned hybrid signature."""

    version: int
    ecc_signature: bytes
    pqc_signature: bytes

    def encode(self) -> bytes:
        return HybridWallet.encode_signature(
            self.ecc_signature,
            self.pqc_signature,
            version=self.version,
        )


class HybridWallet:
    """Coordinate ECC and PQC signatures for one in-memory wallet."""

    signature_version = SIGNATURE_VERSION

    def __init__(
        self,
        pqc_signer: Optional[Any] = None,
        ecdsa: Optional[ECDSAModule] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.ecc = ecdsa or ECDSAModule()
        self.pqc = pqc_signer or DilithiumSigner(security_level=3)
        self._clock = clock
        self.public_keys: Dict[str, HybridPublicKey] = {}
        self.private_keys: Dict[str, HybridPrivateKey] = {}
        # Keep the original attribute name for callers of the PoC API.
        self.keys = self.public_keys

    @staticmethod
    def _key_id(ecc_pubkey: bytes, pqc_pubkey: bytes) -> str:
        material = (
            b"bitcoin-hybrid-key-v1"
            + len(ecc_pubkey).to_bytes(2, "big")
            + ecc_pubkey
            + len(pqc_pubkey).to_bytes(4, "big")
            + pqc_pubkey
        )
        return hashlib.sha256(material).hexdigest()

    def generate_hybrid_keypair(self) -> HybridPublicKey:
        """Generate, retain, and return a hybrid public key."""
        ecc_private, ecc_public = self.ecc.generate_keypair()
        pqc_public, pqc_private = self.pqc.generate_keypair()
        ecc_private = _as_bytes(ecc_private, "ecc_private")
        ecc_public = _as_bytes(ecc_public, "ecc_public")
        pqc_public = _as_bytes(pqc_public, "pqc_public")
        pqc_private = _as_bytes(pqc_private, "pqc_private")
        if len(ecc_private) != 32:
            raise ValueError("ECC implementation returned an invalid private key")
        if len(ecc_public) not in (33, 65):
            raise ValueError("ECC implementation returned an invalid public key")

        created_at = int(self._clock())
        key_id = self._key_id(ecc_public, pqc_public)
        algorithm = str(getattr(self.pqc, "algorithm_name", "ML-DSA-65"))
        private_key = HybridPrivateKey(
            ecc_privkey=ecc_private,
            pqc_privkey=pqc_private,
            key_id=key_id,
            created_at=created_at,
            pqc_algorithm=algorithm,
        )
        public_key = HybridPublicKey(
            ecc_pubkey=ecc_public,
            pqc_pubkey=pqc_public,
            key_id=key_id,
            created_at=created_at,
            pqc_algorithm=algorithm,
        )
        self.private_keys[key_id] = private_key
        self.public_keys[key_id] = public_key
        return public_key

    def get_public_key(self, key_id: str) -> Optional[HybridPublicKey]:
        return self.public_keys.get(key_id)

    def get_private_key(self, key_id: str) -> Optional[HybridPrivateKey]:
        return self.private_keys.get(key_id)

    def remove_key(self, key_id: str) -> bool:
        removed = key_id in self.public_keys or key_id in self.private_keys
        self.public_keys.pop(key_id, None)
        self.private_keys.pop(key_id, None)
        return removed

    @staticmethod
    def encode_signature(
        ecc_signature: bytes,
        pqc_signature: bytes,
        version: int = SIGNATURE_VERSION,
    ) -> bytes:
        """Encode two signatures with bounded, unambiguous lengths."""
        ecc_signature = _as_bytes(ecc_signature, "ecc_signature")
        pqc_signature = _as_bytes(pqc_signature, "pqc_signature")
        if version != SIGNATURE_VERSION:
            raise ValueError(f"Unsupported hybrid signature version: {version}")
        if len(ecc_signature) > 0xFFFF or len(pqc_signature) > 0xFFFF:
            raise ValueError("Hybrid signature components must fit in 16-bit lengths")
        return (
            _SIGNATURE_HEADER.pack(version, len(ecc_signature))
            + ecc_signature
            + len(pqc_signature).to_bytes(_LENGTH_FIELD_SIZE, "big")
            + pqc_signature
        )

    @staticmethod
    def decode_signature(signature: bytes) -> HybridSignature:
        """Decode and strictly validate a versioned hybrid signature."""
        signature = _as_bytes(signature, "signature")
        if len(signature) < _SIGNATURE_HEADER.size + _LENGTH_FIELD_SIZE + 1:
            raise ValueError("Hybrid signature is truncated")
        version, ecc_length = _SIGNATURE_HEADER.unpack_from(signature)
        if version != SIGNATURE_VERSION:
            raise ValueError(f"Unsupported hybrid signature version: {version}")
        ecc_start = _SIGNATURE_HEADER.size
        pqc_length_offset = ecc_start + ecc_length
        if pqc_length_offset + _LENGTH_FIELD_SIZE > len(signature):
            raise ValueError("Hybrid signature is truncated before PQC length")
        ecc_signature = signature[ecc_start:pqc_length_offset]
        pqc_length = int.from_bytes(
            signature[pqc_length_offset:pqc_length_offset + _LENGTH_FIELD_SIZE],
            "big",
        )
        pqc_start = pqc_length_offset + _LENGTH_FIELD_SIZE
        end = pqc_start + pqc_length
        if pqc_length == 0 or end != len(signature):
            raise ValueError("Hybrid signature has an invalid PQC component")
        return HybridSignature(
            version=version,
            ecc_signature=ecc_signature,
            pqc_signature=signature[pqc_start:end],
        )

    def sign_transaction_hybrid(self, tx_data: bytes, key_id: str) -> bytes:
        """Sign transaction bytes with both the ECC and PQC private keys."""
        private_key = self.private_keys.get(key_id)
        if private_key is None:
            raise KeyError(f"Unknown hybrid key: {key_id}")
        tx_data = _as_bytes(tx_data, "tx_data")
        ecc_signature = self.ecc.sign(tx_data, private_key.ecc_privkey)
        pqc_signature = self.pqc.sign(tx_data, private_key.pqc_privkey)
        return self.encode_signature(ecc_signature, pqc_signature)

    def verify_transaction_hybrid(
        self,
        tx_data: bytes,
        signature: bytes,
        pubkey: HybridPublicKey,
    ) -> bool:
        """Return true only when both signatures validate."""
        try:
            tx_data = _as_bytes(tx_data, "tx_data")
            decoded = self.decode_signature(signature)
            return self.ecc.verify(
                tx_data,
                decoded.ecc_signature,
                pubkey.ecc_pubkey,
            ) and self.pqc.verify(
                tx_data,
                decoded.pqc_signature,
                pubkey.pqc_pubkey,
            )
        except (TypeError, ValueError, AttributeError):
            return False

    # Short aliases make the object convenient for transaction integrations.
    sign = sign_transaction_hybrid
    verify = verify_transaction_hybrid