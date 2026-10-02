"""Security and compatibility tests for key management."""

import json
import os

import pytest

from src.key_management import KeyStoreError, SecureKeyStore, SeedPhraseManager


def sample_key(key_id="key-one"):
    return {
        "version": 1,
        "ecc_privkey": "11" * 32,
        "pqc_privkey": "22" * 64,
        "ecc_pubkey": "03" + "33" * 32,
        "pqc_pubkey": "44" * 64,
        "key_id": key_id,
        "created_at": 1_700_000_000,
        "pqc_algorithm": "ML-DSA-65",
    }


def test_key_store_encrypts_and_retrieves_without_leaking_private_material(tmp_path):
    path = tmp_path / "keys.json"
    store = SecureKeyStore("correct horse battery", str(path))
    key = sample_key()

    assert store.store_hybrid_key(key["key_id"], key, {"purpose": "test"})
    assert store.retrieve_hybrid_key(key["key_id"]) == key
    assert store.get_key_metadata(key["key_id"])["metadata"]["purpose"] == "test"
    assert store.export_public_keys(key["key_id"]) == {
        "key_id": key["key_id"],
        "ecc_pubkey": key["ecc_pubkey"],
        "pqc_pubkey": key["pqc_pubkey"],
        "pqc_algorithm": key["pqc_algorithm"],
        "created_at": key["created_at"],
    }
    assert key["ecc_privkey"] not in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600


def test_key_store_uses_random_salts_and_wrong_password_cannot_decrypt(tmp_path):
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    key = sample_key()
    first = SecureKeyStore("same password", str(first_path))
    second = SecureKeyStore("same password", str(second_path))
    assert first.store_hybrid_key(key["key_id"], key)
    assert second.store_hybrid_key(key["key_id"], key)

    first_doc = json.loads(first_path.read_text())
    second_doc = json.loads(second_path.read_text())
    assert first_doc["salt"] != second_doc["salt"]
    assert SecureKeyStore("wrong password", str(first_path)).retrieve_hybrid_key(
        key["key_id"]
    ) is None


def test_key_rotation_and_password_change_preserve_metadata(tmp_path):
    path = tmp_path / "keys.json"
    store = SecureKeyStore("old password", str(path))
    first = sample_key("first")
    second = sample_key("second")
    assert store.store_hybrid_key("first", first, {"label": "old"})
    assert store.rotate_key("first", second)
    assert store.get_key_metadata("second")["metadata"]["rotated_from"] == "first"
    assert store.change_master_password("new password")
    assert store.retrieve_hybrid_key("first") == first
    assert store.retrieve_hybrid_key("second") == second
    assert SecureKeyStore("old password", str(path)).retrieve_hybrid_key("first") is None
    assert SecureKeyStore("new password", str(path)).retrieve_hybrid_key("second") == second
    assert store.delete_key("first")
    assert store.list_key_ids() == ["second"]


def test_key_store_rejects_mismatched_key_ids_and_invalid_documents(tmp_path):
    path = tmp_path / "keys.json"
    store = SecureKeyStore("correct password", str(path))
    assert not store.store_hybrid_key("different", sample_key("key-one"))

    path.write_text("{}")
    with pytest.raises(KeyStoreError):
        SecureKeyStore("correct password", str(path))


def test_bip39_known_vector_and_seed_derivation():
    manager = SeedPhraseManager()
    entropy = bytes(16)
    phrase = manager.entropy_to_mnemonic(entropy)
    assert phrase == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    assert manager.validate_mnemonic(phrase)
    recovered, valid = manager.mnemonic_to_entropy(phrase)
    assert valid
    assert recovered == entropy
    assert len(manager.derive_seed_bytes(phrase)) == 64
    assert not manager.validate_mnemonic(phrase.replace("about", "abandon"))


def test_bip39_generation_supports_12_and_24_words():
    manager = SeedPhraseManager()
    twelve, twelve_seed = manager.generate_wallet_seed(12)
    twenty_four, twenty_four_seed = manager.generate_wallet_seed(24)
    assert len(twelve.split()) == 12
    assert len(twenty_four.split()) == 24
    assert len(twelve_seed) == 64
    assert len(twenty_four_seed) == 64


def test_bip39_rejects_invalid_inputs():
    manager = SeedPhraseManager()
    with pytest.raises(ValueError):
        manager.generate_entropy(15)
    with pytest.raises(TypeError):
        manager.entropy_to_mnemonic("not bytes")
    with pytest.raises(ValueError):
        manager.entropy_to_mnemonic(bytes(15))
    assert manager.mnemonic_to_entropy(None) == (None, False)
    assert manager.mnemonic_to_entropy("abandon") == (None, False)
    with pytest.raises(ValueError):
        manager.derive_seed_bytes("abandon")
    with pytest.raises(TypeError):
        manager.derive_seed_bytes(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            123,
        )
    assert "wordlist_size=2048" in repr(manager)


def test_key_store_handles_missing_keys_and_seed_phrase_requests(tmp_path):
    store = SecureKeyStore("correct password", str(tmp_path / "keys.json"))
    assert store.retrieve_hybrid_key("missing") is None
    assert store.get_key_metadata("missing") is None
    assert not store.delete_key("missing")
    assert not store.rotate_key("missing", sample_key("new"))
    assert not store.change_master_password("short")
    with pytest.raises(KeyError):
        store.generate_seed_phrase("missing")
    assert len(store.generate_seed_phrase(num_words=12).split()) == 12


def test_key_store_rejects_tampered_records(tmp_path):
    path = tmp_path / "keys.json"
    store = SecureKeyStore("correct password", str(path))
    key = sample_key()
    assert store.store_hybrid_key(key["key_id"], key)
    document = json.loads(path.read_text())
    document["keys"][key["key_id"]]["encrypted"] = "not-valid-fernet"
    path.write_text(json.dumps(document))
    assert store.retrieve_hybrid_key(key["key_id"]) is None