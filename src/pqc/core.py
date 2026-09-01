"""Adapters for the NIST post-quantum algorithms used by the wallet.

The project deliberately does not provide a cryptographic fallback.  Random
bytes with a PQC-shaped length are not keys, signatures, or ciphertexts.  A
runtime without liboqs therefore fails explicitly with
``PQCBackendUnavailable``.

The adapter supports the current ML-DSA / ML-KEM names and the legacy
Dilithium / Kyber names exposed by older liboqs-python releases.  Public API
methods use raw ``bytes`` and return ``(public_key, private_key)`` for key
generation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import importlib
from typing import Any, Mapping, Optional, Tuple


class PQCBackendUnavailable(RuntimeError):
    """Raised when the liboqs native backend cannot be loaded."""


class PQCBackendError(RuntimeError):
    """Raised when liboqs rejects a cryptographic operation."""


_oqs: Any = None
_backend_error: Optional[BaseException] = None
_backend_loaded = False


def _load_backend() -> Any:
    """Load liboqs once and turn loader failures into an actionable error."""

    global _oqs, _backend_error, _backend_loaded
    if not _backend_loaded:
        _backend_loaded = True
        try:
            _oqs = importlib.import_module("oqs")
        except BaseException as exc:  # native loaders can raise non-ImportError
            _backend_error = exc

    if _oqs is None:
        detail = f" ({_backend_error})" if _backend_error else ""
        raise PQCBackendUnavailable(
            "The liboqs backend is unavailable"
            f"{detail}. Install liboqs-python and its native liboqs dependencies."
        ) from _backend_error
    return _oqs


def backend_available() -> bool:
    """Return whether the native liboqs backend can be loaded."""

    try:
        _load_backend()
    except PQCBackendUnavailable:
        return False
    return True


def _require_bytes(value: bytes, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    return bytes(value)


def _algorithm_details(instance: Any) -> Mapping[str, Any]:
    details = getattr(instance, "details", {})
    if callable(details):
        details = details()
    return details if isinstance(details, Mapping) else {}


def _select_algorithm(oqs: Any, candidates: Tuple[str, ...]) -> str:
    """Prefer the standardized name, while accepting older liboqs releases."""

    get_enabled = getattr(oqs, "get_enabled_sig_mechanisms", None)
    if get_enabled is None:
        get_enabled = getattr(oqs, "get_enabled_kem_mechanisms", None)
    if get_enabled is not None:
        try:
            enabled = set(get_enabled())
            for candidate in candidates:
                if candidate in enabled:
                    return candidate
        except Exception:
            # Let the constructor below provide the provider's useful error.
            pass
    return candidates[0]


def _new_context(factory: Any, algorithm: str, private_key: Optional[bytes] = None) -> Any:
    """Construct a liboqs context across supported binding API versions."""

    if private_key is not None:
        try:
            return factory(algorithm, secret_key=private_key)
        except TypeError:
            context = factory(algorithm)
            setattr(context, "secret_key", private_key)
            return context
    return factory(algorithm)


class PQCAlgorithm(ABC):
    """Common interface for a PQC primitive that can generate a keypair."""

    @abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Return ``(public_key, private_key)``."""


class DilithiumSigner(PQCAlgorithm):
    """ML-DSA (formerly Dilithium) signature adapter."""

    _ALGORITHMS = {
        2: ("ML-DSA-44", "Dilithium2"),
        3: ("ML-DSA-65", "Dilithium3"),
        5: ("ML-DSA-87", "Dilithium5"),
    }
    _EXPECTED_SIZES = {
        "ML-DSA-44": {"pub": 1312, "priv": 2560, "sig": 2420},
        "ML-DSA-65": {"pub": 1952, "priv": 4032, "sig": 3309},
        "ML-DSA-87": {"pub": 2592, "priv": 4896, "sig": 4627},
        "Dilithium2": {"pub": 1312, "priv": 2528, "sig": 2420},
        "Dilithium3": {"pub": 1952, "priv": 4000, "sig": 3293},
        "Dilithium5": {"pub": 2592, "priv": 4864, "sig": 4595},
    }

    def __init__(self, security_level: int = 3):
        if security_level not in self._ALGORITHMS:
            raise ValueError("Security level must be 2, 3, or 5")
        self.security_level = security_level
        self._oqs = _load_backend()
        self.algorithm_name = _select_algorithm(
            self._oqs, self._ALGORITHMS[security_level]
        )
        self.key_sizes = dict(self._EXPECTED_SIZES[self.algorithm_name])
        self._refresh_sizes()

    def _refresh_sizes(self) -> None:
        try:
            details = _algorithm_details(self._oqs.Signature(self.algorithm_name))
        except Exception:
            return
        for output_name, detail_names in {
            "pub": ("length_public_key", "public_key_length"),
            "priv": ("length_secret_key", "secret_key_length"),
            "sig": ("length_signature", "signature_length"),
        }.items():
            for detail_name in detail_names:
                value = details.get(detail_name)
                if isinstance(value, int) and value > 0:
                    self.key_sizes[output_name] = value
                    break

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        try:
            signer = self._oqs.Signature(self.algorithm_name)
            generated = getattr(signer, "generate_keypair", None)
            if generated is not None:
                result = generated()
                if isinstance(result, tuple) and len(result) == 2:
                    public_key, private_key = result
                else:
                    public_key = result
                    private_key = self._export_private_key(signer)
            else:
                public_key = signer.generate_keyset()
                private_key = self._export_private_key(signer)
            public_key = _require_bytes(public_key, "public_key")
            private_key = _require_bytes(private_key, "private_key")
            self._validate_key_size(public_key, "public", self.key_sizes["pub"])
            self._validate_key_size(private_key, "private", self.key_sizes["priv"])
            return public_key, private_key
        except PQCBackendError:
            raise
        except Exception as exc:
            raise PQCBackendError(
                f"{self.algorithm_name} key generation failed: {exc}"
            ) from exc

    @staticmethod
    def _export_private_key(signer: Any) -> bytes:
        exporter = getattr(signer, "export_secret_key", None)
        if exporter is not None:
            return exporter()
        legacy_exporter = getattr(signer, "secret_key", None)
        if callable(legacy_exporter):
            return legacy_exporter()
        if isinstance(legacy_exporter, (bytes, bytearray)):
            return bytes(legacy_exporter)
        raise PQCBackendError("liboqs did not expose the generated secret key")

    @staticmethod
    def _validate_key_size(value: bytes, name: str, expected: int) -> None:
        if len(value) != expected:
            raise ValueError(
                f"Invalid {name} key size: expected {expected}, got {len(value)}"
            )

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        message = _require_bytes(message, "message")
        private_key = _require_bytes(private_key, "private_key")
        self._validate_key_size(private_key, "private", self.key_sizes["priv"])
        try:
            signer = _new_context(self._oqs.Signature, self.algorithm_name, private_key)
            signature = _require_bytes(signer.sign(message), "signature")
            self._validate_key_size(signature, "signature", self.key_sizes["sig"])
            return signature
        except Exception as exc:
            raise PQCBackendError(f"{self.algorithm_name} signing failed: {exc}") from exc

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        try:
            message = _require_bytes(message, "message")
            signature = _require_bytes(signature, "signature")
            public_key = _require_bytes(public_key, "public_key")
            if len(public_key) != self.key_sizes["pub"]:
                return False
            if len(signature) != self.key_sizes["sig"]:
                return False
            verifier = self._oqs.Signature(self.algorithm_name)
            try:
                return bool(verifier.verify(message, signature, public_key))
            except TypeError:
                setattr(verifier, "public_key", public_key)
                return bool(verifier.verify(message, signature))
        except Exception:
            return False


class KyberKEM(PQCAlgorithm):
    """ML-KEM (formerly Kyber) key encapsulation adapter."""

    _ALGORITHMS = {
        512: ("ML-KEM-512", "Kyber512"),
        768: ("ML-KEM-768", "Kyber768"),
        1024: ("ML-KEM-1024", "Kyber1024"),
    }
    _EXPECTED_SIZES = {
        "ML-KEM-512": {"pub": 800, "priv": 1632, "ct": 768},
        "ML-KEM-768": {"pub": 1184, "priv": 2400, "ct": 1088},
        "ML-KEM-1024": {"pub": 1568, "priv": 3168, "ct": 1568},
        "Kyber512": {"pub": 800, "priv": 1632, "ct": 768},
        "Kyber768": {"pub": 1184, "priv": 2400, "ct": 1088},
        "Kyber1024": {"pub": 1568, "priv": 3168, "ct": 1568},
    }
    SHARED_SECRET_SIZE = 32

    def __init__(self, security_level: int = 768):
        if security_level not in self._ALGORITHMS:
            raise ValueError("Security level must be 512, 768, or 1024")
        self.security_level = security_level
        self._oqs = _load_backend()
        self.algorithm_name = _select_algorithm(
            self._oqs, self._ALGORITHMS[security_level]
        )
        self.key_sizes = dict(self._EXPECTED_SIZES[self.algorithm_name])
        self._refresh_sizes()

    def _refresh_sizes(self) -> None:
        try:
            details = _algorithm_details(self._oqs.KeyEncapsulation(self.algorithm_name))
        except Exception:
            return
        for output_name, detail_names in {
            "pub": ("length_public_key", "public_key_length"),
            "priv": ("length_secret_key", "secret_key_length"),
            "ct": ("length_ciphertext", "ciphertext_length"),
        }.items():
            for detail_name in detail_names:
                value = details.get(detail_name)
                if isinstance(value, int) and value > 0:
                    self.key_sizes[output_name] = value
                    break

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        try:
            kem = self._oqs.KeyEncapsulation(self.algorithm_name)
            generated = kem.generate_keypair()
            if isinstance(generated, tuple) and len(generated) == 2:
                public_key, private_key = generated
            else:
                public_key = generated
                private_key = self._export_private_key(kem)
            public_key = _require_bytes(public_key, "public_key")
            private_key = _require_bytes(private_key, "private_key")
            self._validate_size(public_key, "public", self.key_sizes["pub"])
            self._validate_size(private_key, "private", self.key_sizes["priv"])
            return public_key, private_key
        except Exception as exc:
            raise PQCBackendError(
                f"{self.algorithm_name} key generation failed: {exc}"
            ) from exc

    @staticmethod
    def _export_private_key(kem: Any) -> bytes:
        exporter = getattr(kem, "export_secret_key", None)
        if exporter is not None:
            return exporter()
        legacy_exporter = getattr(kem, "secret_key", None)
        if callable(legacy_exporter):
            return legacy_exporter()
        if isinstance(legacy_exporter, (bytes, bytearray)):
            return bytes(legacy_exporter)
        raise PQCBackendError("liboqs did not expose the generated secret key")

    @staticmethod
    def _validate_size(value: bytes, name: str, expected: int) -> None:
        if len(value) != expected:
            raise ValueError(
                f"Invalid {name} key size: expected {expected}, got {len(value)}"
            )

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        public_key = _require_bytes(public_key, "public_key")
        self._validate_size(public_key, "public", self.key_sizes["pub"])
        try:
            kem = self._oqs.KeyEncapsulation(self.algorithm_name)
            try:
                ciphertext, shared_secret = kem.encap_secret(public_key)
            except TypeError:
                setattr(kem, "public_key", public_key)
                ciphertext, shared_secret = kem.encap_secret()
            ciphertext = _require_bytes(ciphertext, "ciphertext")
            shared_secret = _require_bytes(shared_secret, "shared_secret")
            self._validate_size(ciphertext, "ciphertext", self.key_sizes["ct"])
            if len(shared_secret) != self.SHARED_SECRET_SIZE:
                raise PQCBackendError(
                    f"Invalid shared secret size: expected {self.SHARED_SECRET_SIZE}, "
                    f"got {len(shared_secret)}"
                )
            return ciphertext, shared_secret
        except Exception as exc:
            raise PQCBackendError(
                f"{self.algorithm_name} encapsulation failed: {exc}"
            ) from exc

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        ciphertext = _require_bytes(ciphertext, "ciphertext")
        private_key = _require_bytes(private_key, "private_key")
        self._validate_size(ciphertext, "ciphertext", self.key_sizes["ct"])
        self._validate_size(private_key, "private", self.key_sizes["priv"])
        try:
            kem = _new_context(
                self._oqs.KeyEncapsulation, self.algorithm_name, private_key
            )
            shared_secret = _require_bytes(kem.decap_secret(ciphertext), "shared_secret")
            if len(shared_secret) != self.SHARED_SECRET_SIZE:
                raise PQCBackendError(
                    f"Invalid shared secret size: expected {self.SHARED_SECRET_SIZE}, "
                    f"got {len(shared_secret)}"
                )
            return shared_secret
        except Exception as exc:
            raise PQCBackendError(
                f"{self.algorithm_name} decapsulation failed: {exc}"
            ) from exc

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        raise NotImplementedError("KEMs do not sign messages; use DilithiumSigner")

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        raise NotImplementedError("KEMs do not verify signatures; use DilithiumSigner")


class PQCModule:
    """Convenience facade exposing the configured ML-DSA and ML-KEM adapters."""

    def __init__(self, dilithium_level: int = 3, kyber_level: int = 768):
        self.dilithium = DilithiumSigner(dilithium_level)
        self.kyber = KyberKEM(kyber_level)

    def get_algorithm_info(self) -> dict[str, Any]:
        return {
            "backend": "liboqs",
            "dilithium": {
                "name": self.dilithium.algorithm_name,
                "level": self.dilithium.security_level,
                "pubkey_size": self.dilithium.key_sizes["pub"],
                "privkey_size": self.dilithium.key_sizes["priv"],
                "signature_size": self.dilithium.key_sizes["sig"],
            },
            "kyber": {
                "name": self.kyber.algorithm_name,
                "level": self.kyber.security_level,
                "pubkey_size": self.kyber.key_sizes["pub"],
                "privkey_size": self.kyber.key_sizes["priv"],
                "ciphertext_size": self.kyber.key_sizes["ct"],
                "shared_secret_size": self.kyber.SHARED_SECRET_SIZE,
            },
        }