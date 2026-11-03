"""Tests for BIP340 Schnorr and BIP341 Taproot primitives."""

import pytest

from src.bitcoin.integration import TransactionInput, TransactionOutput
from src.bitcoin.taproot import (
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_DEFAULT,
    taproot_control_block,
    tapleaf_hash,
    tapbranch_hash,
    taproot_keypath_sign,
    taproot_keypath_verify,
    taproot_scriptpath_sign,
    taproot_scriptpath_witness,
    taproot_sighash,
    taproot_tweak_private_key,
    taproot_tweak_pubkey,
    verify_taproot_control_block,
    xonly_public_key,
    schnorr_sign,
    schnorr_verify,
)


PRIVATE_KEY = bytes.fromhex("00" * 31 + "03")
MESSAGE = bytes(32)
AUX_RAND = bytes(range(32))


def _input(sequence=0xFFFFFFFE):
    return TransactionInput(
        previous_tx_hash=bytes(range(32)),
        previous_output_index=1,
        script_pubkey=b"\x51",
        sequence=sequence,
    )


def test_xonly_public_key_matches_bip340_secp256k1_vector():
    assert xonly_public_key(PRIVATE_KEY) == bytes.fromhex(
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    )


def test_bip340_signature_is_deterministic_with_explicit_aux_rand():
    public_key = xonly_public_key(PRIVATE_KEY)
    signature = schnorr_sign(MESSAGE, PRIVATE_KEY, aux_rand=AUX_RAND)
    assert len(signature) == 64
    assert schnorr_verify(MESSAGE, signature, public_key)
    assert signature == schnorr_sign(MESSAGE, PRIVATE_KEY, aux_rand=AUX_RAND)
    assert not schnorr_verify(MESSAGE, signature[:-1], public_key)


def test_bip340_rejects_invalid_message_and_key_lengths():
    with pytest.raises(ValueError):
        schnorr_sign(b"short", PRIVATE_KEY, aux_rand=AUX_RAND)
    with pytest.raises(ValueError):
        schnorr_sign(MESSAGE, bytes(31), aux_rand=AUX_RAND)
    assert not schnorr_verify(MESSAGE, b"" + bytes(63), xonly_public_key(PRIVATE_KEY))


def test_taproot_tweak_private_and_public_paths_match():
    merkle_root = bytes.fromhex("11" * 32)
    internal_key = xonly_public_key(PRIVATE_KEY)
    tweaked_public = taproot_tweak_pubkey(internal_key, merkle_root)
    tweaked_private, parity = taproot_tweak_private_key(PRIVATE_KEY, merkle_root)
    assert tweaked_public.parity == parity
    assert xonly_public_key(tweaked_private) == tweaked_public.output_key


def test_taproot_keypath_signatures_verify_against_tweaked_output_key():
    merkle_root = bytes.fromhex("11" * 32)
    signature = taproot_keypath_sign(
        MESSAGE,
        PRIVATE_KEY,
        merkle_root=merkle_root,
        aux_rand=AUX_RAND,
        sighash_type=SIGHASH_ALL,
    )
    internal_key = xonly_public_key(PRIVATE_KEY)
    output_key = taproot_tweak_pubkey(internal_key, merkle_root).output_key
    assert len(signature) == 65
    assert signature[-1] == SIGHASH_ALL
    assert schnorr_verify(MESSAGE, signature[:64], output_key)
    assert taproot_keypath_verify(MESSAGE, signature, internal_key, merkle_root=merkle_root)
    assert taproot_keypath_verify(
        MESSAGE,
        signature[:-1],
        internal_key,
        merkle_root=merkle_root,
    )
    assert not taproot_keypath_verify(
        MESSAGE,
        signature[:-1],
        internal_key,
        merkle_root=merkle_root,
        sighash_type=SIGHASH_ALL,
    )


def test_bip341_sighash_commits_to_prevouts_and_transaction_context():
    inputs = [_input(), _input(sequence=0xFFFFFFFD)]
    outputs = [
        TransactionOutput(50_000, b"\x51"),
        TransactionOutput(25_000, b"\x51\x20" + bytes(32)),
    ]
    prevouts = [
        TransactionOutput(60_000, b"\x00\x14" + bytes(20)),
        TransactionOutput(30_000, b"\x00\x14" + bytes(20)),
    ]
    digest = taproot_sighash(inputs, outputs, prevouts, 0)
    assert len(digest) == 32
    assert digest != taproot_sighash(inputs, outputs, prevouts, 1)
    assert digest != taproot_sighash(inputs, [TransactionOutput(50_001, b"\x51"), outputs[1]], prevouts, 0)
    assert digest != taproot_sighash(inputs, outputs, [TransactionOutput(60_001, prevouts[0].script_pubkey), prevouts[1]], 0)


def test_bip341_sighash_modes_and_annex_validation():
    inputs = [_input()]
    outputs = [TransactionOutput(50_000, b"\x51")]
    prevouts = [TransactionOutput(60_000, b"\x00\x14" + bytes(20))]
    anyone = taproot_sighash(
        inputs,
        outputs,
        prevouts,
        0,
        sighash_type=SIGHASH_ALL | SIGHASH_ANYONECANPAY,
    )
    annex = taproot_sighash(
        inputs,
        outputs,
        prevouts,
        0,
        annex=b"\x50annex",
    )
    assert anyone != annex
    with pytest.raises(ValueError):
        taproot_sighash(inputs, outputs, prevouts, 0, annex=b"\x51bad")
    with pytest.raises(ValueError):
        taproot_sighash(inputs, outputs, prevouts, 0, sighash_type=SIGHASH_DEFAULT | SIGHASH_ANYONECANPAY)


def test_bip342_script_path_sighash_commits_to_leaf_and_codeseparator():
    inputs = [_input()]
    outputs = [TransactionOutput(50_000, b"\x51")]
    prevouts = [TransactionOutput(60_000, b"\x00\x14" + bytes(20))]
    leaf = tapleaf_hash(b"\xac")
    baseline = taproot_sighash(
        inputs,
        outputs,
        prevouts,
        0,
        ext_flag=1,
        tapleaf_hash=leaf,
    )
    assert baseline != taproot_sighash(
        inputs,
        outputs,
        prevouts,
        0,
        ext_flag=1,
        tapleaf_hash=bytes.fromhex("11" * 32),
    )
    assert baseline != taproot_sighash(
        inputs,
        outputs,
        prevouts,
        0,
        ext_flag=1,
        tapleaf_hash=leaf,
        codeseparator_pos=4,
    )


def test_tapleaf_branch_and_control_block_commitment():
    internal_key = xonly_public_key(PRIVATE_KEY)
    script = b"\x51"
    leaf = tapleaf_hash(script)
    sibling = bytes.fromhex("42" * 32)
    root = tapbranch_hash(leaf, sibling)
    tweaked = taproot_tweak_pubkey(internal_key, root)
    control = taproot_control_block(internal_key, tweaked.parity, [sibling])
    assert len(control) == 65
    assert verify_taproot_control_block(script, control, tweaked.output_key)
    assert not verify_taproot_control_block(b"\x00", control, tweaked.output_key)
    assert not verify_taproot_control_block(script, control, bytes(32))


def test_bip341_official_script_leaf_and_control_block_vector():
    internal_key = bytes.fromhex(
        "187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27"
    )
    script = bytes.fromhex(
        "20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac"
    )
    leaf_hash = tapleaf_hash(script)
    assert leaf_hash.hex() == (
        "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21"
    )
    output_key = bytes.fromhex(
        "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3"
    )
    control = bytes.fromhex(
        "c1187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27"
    )
    assert verify_taproot_control_block(script, control, output_key)


def test_taproot_script_path_signature_and_witness_layout():
    script = b"\xac"
    control = b"\xc0" + xonly_public_key(PRIVATE_KEY)
    signature = taproot_scriptpath_sign(
        MESSAGE,
        PRIVATE_KEY,
        aux_rand=bytes(32),
        sighash_type=SIGHASH_ALL,
    )
    assert len(signature) == 65
    assert schnorr_verify(MESSAGE, signature[:64], xonly_public_key(PRIVATE_KEY))
    witness = taproot_scriptpath_witness(
        [signature, b"\x01"],
        script,
        control,
        annex=b"\x50annex",
    )
    assert witness == (signature, b"\x01", script, control, b"\x50annex")
