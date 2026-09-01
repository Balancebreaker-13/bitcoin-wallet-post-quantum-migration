"""Contract tests for the liboqs-backed PQC adapters."""

import pytest

from src.pqc.core import (
    DilithiumSigner,
    KyberKEM,
    PQCBackendUnavailable,
    backend_available,
)


def test_security_levels_are_validated_before_backend_use():
    with pytest.raises(ValueError):
        DilithiumSigner(4)
    with pytest.raises(ValueError):
        KyberKEM(256)


def test_backend_failure_is_explicit():
    if backend_available():
        pytest.skip("liboqs is available; round-trip tests cover the backend")
    with pytest.raises(PQCBackendUnavailable):
        DilithiumSigner()
    with pytest.raises(PQCBackendUnavailable):
        KyberKEM()


def test_dilithium_round_trip():
    if not backend_available():
        pytest.skip("liboqs is not available")
    signer = DilithiumSigner(3)
    public_key, private_key = signer.generate_keypair()
    message = b"post-quantum wallet transaction"
    signature = signer.sign(message, private_key)

    assert signer.verify(message, signature, public_key)
    assert not signer.verify(b"tampered", signature, public_key)


def test_kyber_round_trip():
    if not backend_available():
        pytest.skip("liboqs is not available")
    kem = KyberKEM(768)
    public_key, private_key = kem.generate_keypair()
    ciphertext, sender_secret = kem.encapsulate(public_key)
    recipient_secret = kem.decapsulate(ciphertext, private_key)

    assert sender_secret == recipient_secret


def test_malformed_keys_are_rejected_without_backend_operation():
    if not backend_available():
        pytest.skip("liboqs is not available")
    signer = DilithiumSigner(3)
    with pytest.raises(ValueError):
        signer.sign(b"message", b"not-a-private-key")
    assert not signer.verify(b"message", b"bad", b"bad")
    kem = KyberKEM(768)
    with pytest.raises(ValueError):
        kem.encapsulate(b"not-a-public-key")