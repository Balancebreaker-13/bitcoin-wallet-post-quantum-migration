"""Tests for BIP340 Schnorr and BIP341 Taproot primitives."""

import pytest

from src.bitcoin.integration import TransactionInput, TransactionOutput
from src.bitcoin.taproot import (
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_DEFAULT,
    TaprootOutputKey,
    encode_taproot_signature,
    schnorr_sign,
    schnorr_verify,
    tapbranch_hash,
    tapleaf_hash,
    taproot_control_block,
    tagged_hash,
    taproot_keypath_sign,
    taproot_scriptpath_sign,
    taproot_scriptpath_witness,
    taproot_sighash,
    taproot_tweak_private_key,
    taproot_tweak_pubkey,
    verify_taproot_control_block,
    xonly_public_key,
)


PRIVATE_KEY = bytes.fromhex("00" * 31 + "03")
PUBLIC_KEY = bytes.fromhex(
    "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
)
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


@pytest.mark.parametrize(
    ("private_key", "public_key", "aux_rand", "message", "expected_signature"),
    [
        (
            "00" * 31 + "03",
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            "00" * 32,
            "00" * 32,
            "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
        ),
        (
            "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
            "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            "00" * 31 + "01",
            "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a",
        ),
        (
            "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
            "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
            "c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906",
            "7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c",
            "5831aae ed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7".replace(" ", ""),
        ),
    ],
)
def test_bip340_official_signing_vectors(
    private_key,
    public_key,
    aux_rand,
    message,
    expected_signature,
):
    private_key = bytes.fromhex(private_key)
    public_key = bytes.fromhex(public_key)
    aux_rand = bytes.fromhex(aux_rand)
    message = bytes.fromhex(message)
    expected_signature = bytes.fromhex(expected_signature)
    signature = schnorr_sign(message, private_key, aux_rand=aux_rand)
    assert signature == expected_signature
    assert schnorr_verify(message, signature, public_key)


def test_bip340_signature_is_deterministic_with_explicit_aux_rand():
    signature = schnorr_sign(MESSAGE, PRIVATE_KEY, aux_rand=AUX_RAND)
    public_key = xonly_public_key(PRIVATE_KEY)
    assert len(signature) == 64
    assert schnorr_verify(MESSAGE, signature, public_key)
    assert signature == schnorr_sign(MESSAGE, PRIVATE_KEY, aux_rand=AUX_RAND)
    assert not schnorr_verify(b"\x01" + MESSAGE[1:], signature, public_key)
    assert not schnorr_verify(MESSAGE, signature[:-1], public_key)


def test_bip340_rejects_noncanonical_and_invalid_keys():
    signature = schnorr_sign(MESSAGE, PRIVATE_KEY, aux_rand=bytes(32))
    assert not schnorr_verify(MESSAGE, signature, bytes(32))
    assert not schnorr_verify(MESSAGE, bytes(32) + signature[32:], PUBLIC_KEY)
    assert not schnorr_verify(MESSAGE, signature[:32] + (2**256 - 1).to_bytes(32, "big"), PUBLIC_KEY)
    with pytest.raises(ValueError):
        schnorr_sign(MESSAGE, bytes(32), aux_rand=bytes(32))
    with pytest.raises(ValueError):
        schnorr_sign(MESSAGE, PRIVATE_KEY, aux_rand=b"short")


def test_taproot_tweak_private_and_public_paths_match():
    merkle_root = bytes.fromhex("11" * 32)
    public_key = xonly_public_key(PRIVATE_KEY)
    tweaked_public = taproot_tweak_pubkey(public_key, merkle_root)
    tweaked_private, parity = taproot_tweak_private_key(PRIVATE_KEY, merkle_root)
    assert isinstance(tweaked_public, TaprootOutputKey)
    assert parity == tweaked_public.parity
    assert xonly_public_key(tweaked_private) == tweaked_public.output_key


def test_taproot_private_tweak_normalizes_odd_internal_point_in_libsecp():
    odd_y_private_key = (6).to_bytes(32, "big")
    internal_key = xonly_public_key(odd_y_private_key)
    tweaked_public = taproot_tweak_pubkey(internal_key)
    tweaked_private, parity = taproot_tweak_private_key(odd_y_private_key)
    assert xonly_public_key(tweaked_private) == tweaked_public.output_key
    assert parity == tweaked_public.parity


def test_bip341_official_taproot_output_key_vector():
    internal_key = bytes.fromhex(
        "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d"
    )
    tweaked = taproot_tweak_pubkey(internal_key)
    assert tweaked.tweak.to_bytes(32, "big").hex() == (
        "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70"
    )
    assert tweaked.output_key.hex() == (
        "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
    )


def test_taproot_keypath_signature_and_optional_sighash_byte():
    signature = taproot_keypath_sign(
        MESSAGE,
        PRIVATE_KEY,
        aux_rand=bytes(32),
        sighash_type=SIGHASH_ALL,
    )
    output_key = taproot_tweak_pubkey(xonly_public_key(PRIVATE_KEY)).output_key
    assert len(signature) == 65
    assert signature[-1] == SIGHASH_ALL
    assert schnorr_verify(MESSAGE, signature[:64], output_key)
    assert encode_taproot_signature(signature[:64], SIGHASH_DEFAULT) == signature[:64]


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
    changed_outputs = [TransactionOutput(50_001, b"\x51"), outputs[1]]
    assert digest != taproot_sighash(inputs, changed_outputs, prevouts, 0)
    changed_prevouts = [TransactionOutput(60_001, prevouts[0].script_pubkey), prevouts[1]]
    assert digest != taproot_sighash(inputs, outputs, changed_prevouts, 0)
    assert digest != taproot_sighash(
        inputs,
        outputs,
        prevouts,
        0,
        version=3,
    )
    assert digest != taproot_sighash(
        inputs,
        outputs,
        prevouts,
        0,
        locktime=1,
    )


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
        taproot_sighash(
            inputs,
            outputs,
            prevouts,
            0,
            sighash_type=SIGHASH_DEFAULT | SIGHASH_ANYONECANPAY,
        )
    with pytest.raises(ValueError):
        taproot_sighash(inputs, outputs, prevouts, 0, ext_flag=1)


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


def test_bip340_transaction_signing_requires_a_32_byte_sighash():
    with pytest.raises(ValueError):
        schnorr_sign(b"short message", PRIVATE_KEY, aux_rand=bytes(32))
    assert not schnorr_verify(b"short message", bytes(64), xonly_public_key(PRIVATE_KEY))


def test_tapleaf_branch_and_control_block_commitment():
    internal_key = xonly_public_key(PRIVATE_KEY)
    script = b"\x51"
    leaf = tapleaf_hash(script)
    sibling = bytes.fromhex("42" * 32)
    root = tapbranch_hash(leaf, sibling)
    tweaked = taproot_tweak_pubkey(internal_key, root)
    control = taproot_control_block(
        internal_key,
        tweaked.parity,
        [sibling],
    )
    assert len(control) == 65
    assert verify_taproot_control_block(script, control, tweaked.output_key)
    assert not verify_taproot_control_block(b"\x00", control, tweaked.output_key)
    assert not verify_taproot_control_block(script, control, bytes(32))
    assert tapbranch_hash(leaf, sibling) == tapbranch_hash(sibling, leaf)


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
    assert schnorr_verify(
        MESSAGE,
        signature[:64],
        xonly_public_key(PRIVATE_KEY),
    )
    witness = taproot_scriptpath_witness(
        [signature, b"\x01"],
        script,
        control,
        annex=b"\x50annex",
    )
    assert witness == (signature, b"\x01", script, control, b"\x50annex")