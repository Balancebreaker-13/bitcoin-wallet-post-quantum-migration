"""Tests for the hybrid wallet coordination and wire format."""

import hashlib

import pytest

from src.crypto.ecdsa_module import ECDSAModule
from src.hybrid import HybridWallet


class StubPQCSigner:
    """A deterministic test double; production code always uses liboqs."""

    algorithm_name = "test-ml-dsa"

    def generate_keypair(self):
        return b"pqc-public-key", b"pqc-private-key"

    def sign(self, message, private_key):
        if private_key != b"pqc-private-key":
            raise ValueError("wrong private key")
        return hashlib.sha256(b"pqc-signature:" + message).digest()

    def verify(self, message, signature, public_key):
        return (
            public_key == b"pqc-public-key"
            and signature == hashlib.sha256(b"pqc-signature:" + message).digest()
        )


def test_ecdsa_signatures_are_real_and_tamper_evident():
    ecdsa = ECDSAModule()
    private_key, public_key = ecdsa.generate_keypair()
    message = b"transaction bytes"
    signature = ecdsa.sign(message, private_key)

    assert len(private_key) == 32
    assert len(public_key) == 33
    assert ecdsa.verify(message, signature, public_key)
    assert not ecdsa.verify(b"tampered transaction", signature, public_key)
    assert not ecdsa.verify(message, signature[:-1], public_key)


def test_hybrid_wallet_generates_signs_and_serializes_keys():
    wallet = HybridWallet(
        pqc_signer=StubPQCSigner(),
        clock=lambda: 1_700_000_000,
    )
    public_key = wallet.generate_hybrid_keypair()
    private_key = wallet.get_private_key(public_key.key_id)

    assert private_key is not None
    assert public_key.created_at == 1_700_000_000
    assert public_key.key_id == private_key.key_id
    assert HybridWallet.decode_signature(
        wallet.sign_transaction_hybrid(b"tx", public_key.key_id)
    ).version == 1
    assert HybridWallet.decode_signature(
        wallet.sign_transaction_hybrid(b"tx", public_key.key_id)
    ).pqc_signature
    assert HybridWallet.verify_transaction_hybrid(
        wallet,
        b"tx",
        wallet.sign_transaction_hybrid(b"tx", public_key.key_id),
        public_key,
    )
    assert HybridWallet.verify_transaction_hybrid(
        wallet,
        b"tx",
        wallet.sign_transaction_hybrid(b"tx", public_key.key_id),
        type(public_key).from_dict(public_key.to_dict()),
    )
    assert not wallet.verify_transaction_hybrid(
        b"tampered",
        wallet.sign_transaction_hybrid(b"tx", public_key.key_id),
        public_key,
    )

    restored = type(public_key).from_dict(public_key.to_dict())
    assert restored == public_key
    assert type(private_key).from_dict(private_key.to_dict()) == private_key


@pytest.mark.parametrize(
    "mutator",
    [
        lambda signature: b"\x02" + signature[1:],
        lambda signature: signature[:-1],
        lambda signature: signature + b"\x00",
        lambda signature: signature[:3] + b"\xff\xff",
    ],
)
def test_hybrid_verification_rejects_malformed_signatures(mutator):
    wallet = HybridWallet(pqc_signer=StubPQCSigner(), clock=lambda: 1_700_000_000)
    public_key = wallet.generate_hybrid_keypair()
    signature = wallet.sign_transaction_hybrid(b"tx", public_key.key_id)

    assert not wallet.verify_transaction_hybrid(
        b"tx",
        mutator(signature),
        public_key,
    )


def test_hybrid_wallet_requires_known_private_key():
    wallet = HybridWallet(pqc_signer=StubPQCSigner())
    with pytest.raises(KeyError):
        wallet.sign_transaction_hybrid(b"tx", "missing")