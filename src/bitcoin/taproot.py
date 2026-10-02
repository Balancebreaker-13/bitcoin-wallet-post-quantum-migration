"""BIP340 Schnorr and BIP341 Taproot primitives.

This module deliberately contains only consensus-critical primitives:

* BIP340 x-only public keys, signing, and verification
* BIP341 TapTweak computation for key-path spends
* BIP341 transaction sighash construction

Private-key curve operations use coincurve's libsecp256k1 binding. This does
not replace transaction-policy validation, secure key custody, or independent
cryptographic review.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Optional, Sequence, Tuple

from coincurve import PrivateKey, PublicKeyXOnly
from coincurve._libsecp256k1 import ffi, lib
from coincurve.context import GLOBAL_CONTEXT


FIELD_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SIGHASH_DEFAULT = 0x00
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80
MAX_UINT32 = 0xFFFFFFFF


def _bytes(value: Any, name: str, *, length: Optional[int] = None) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    value = bytes(value)
    if not value:
        raise ValueError(f"{name} must not be empty")
    if length is not None and len(value) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")
    return value


def _sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def tagged_hash(tag: str, message: bytes) -> bytes:
    """Return SHA256(tagged-hash) as defined by BIP340."""
    tag_hash = _sha256(tag.encode("ascii"))
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise TypeError("message must be bytes-like")
    return _sha256(tag_hash + tag_hash + bytes(message))


def _private_scalar(private_key: bytes) -> bytes:
    private_key = _bytes(private_key, "private_key", length=32)
    secret = ffi.new("unsigned char [32]", private_key)
    if not lib.secp256k1_ec_seckey_verify(GLOBAL_CONTEXT.ctx, secret):
        raise ValueError("private_key is outside the secp256k1 scalar range")
    return private_key


def _negate_private_scalar(private_key: bytes) -> bytes:
    """Negate a private scalar using libsecp256k1, not Python arithmetic."""
    secret = ffi.new("unsigned char [32]", private_key)
    if not lib.secp256k1_ec_seckey_negate(GLOBAL_CONTEXT.ctx, secret):
        raise ValueError("private_key is outside the secp256k1 scalar range")
    return bytes(ffi.buffer(secret, 32))


def _message(message: bytes) -> bytes:
    if not isinstance(message, (bytes, bytearray, memoryview)):
        raise TypeError("message must be bytes-like")
    message = bytes(message)
    if len(message) != 32:
        raise ValueError("BIP340 message must be exactly 32 bytes")
    return message


def xonly_public_key(private_key: bytes) -> bytes:
    """Return the 32-byte BIP340 x-only public key for a private scalar."""
    private_key = _private_scalar(private_key)
    return PublicKeyXOnly.from_secret(private_key).format()


def schnorr_sign(
    message: bytes,
    private_key: bytes,
    *,
    aux_rand: Optional[bytes] = None,
) -> bytes:
    """Create a 64-byte BIP340 Schnorr signature for a 32-byte message."""
    message = _message(message)
    private_key = _private_scalar(private_key)
    if aux_rand is not None:
        aux_rand = _bytes(aux_rand, "aux_rand", length=32)
    try:
        return PrivateKey(private_key).sign_schnorr(
            message,
            aux_randomness=aux_rand,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"BIP340 signing failed: {exc}") from exc


def schnorr_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify a BIP340 signature, returning false for every malformed input."""
    try:
        message = _message(message)
        signature = _bytes(signature, "signature", length=64)
        public_key = _bytes(public_key, "public_key", length=32)
        return PublicKeyXOnly(public_key).verify(signature, message)
    except (TypeError, ValueError, OverflowError):
        return False


@dataclass(frozen=True)
class TaprootOutputKey:
    """A tweaked Taproot output key and its control-block parity bit."""

    output_key: bytes
    parity: int
    tweak: int


def _validate_merkle_root(merkle_root: bytes) -> bytes:
    if not isinstance(merkle_root, (bytes, bytearray, memoryview)):
        raise TypeError("merkle_root must be bytes-like")
    merkle_root = bytes(merkle_root)
    if len(merkle_root) not in (0, 32):
        raise ValueError("merkle_root must be empty or exactly 32 bytes")
    return merkle_root


def tapleaf_hash(script: bytes, leaf_version: int = 0xC0) -> bytes:
    """Return the BIP341 TapLeaf hash of a tapscript leaf."""
    if not isinstance(script, (bytes, bytearray, memoryview)):
        raise TypeError("script must be bytes-like")
    script = bytes(script)
    if not isinstance(leaf_version, int) or not 0 <= leaf_version <= 0xFE:
        raise ValueError("leaf_version must fit in an even byte")
    if leaf_version & 1:
        raise ValueError("leaf_version must be even")
    return tagged_hash(
        "TapLeaf",
        bytes([leaf_version]) + _compact_size(len(script)) + script,
    )


def tapbranch_hash(left: bytes, right: bytes) -> bytes:
    """Return the lexicographically ordered BIP341 TapBranch hash."""
    left = _bytes(left, "left", length=32)
    right = _bytes(right, "right", length=32)
    first, second = sorted((left, right))
    return tagged_hash("TapBranch", first + second)


def taproot_control_block(
    internal_key: bytes,
    output_parity: int,
    merkle_path: Sequence[bytes] = (),
    *,
    leaf_version: int = 0xC0,
) -> bytes:
    """Create the control block for one script leaf in a Taproot tree."""
    internal_key = _bytes(internal_key, "internal_key", length=32)
    if output_parity not in (0, 1):
        raise ValueError("output_parity must be 0 or 1")
    if not isinstance(merkle_path, Sequence):
        raise TypeError("merkle_path must be a sequence of 32-byte hashes")
    if len(merkle_path) > 128:
        raise ValueError("Taproot control block has more than 128 merkle nodes")
    if not isinstance(leaf_version, int) or not 0 <= leaf_version <= 0xFE:
        raise ValueError("leaf_version must fit in an even byte")
    if leaf_version & 1:
        raise ValueError("leaf_version must be even")
    path = b"".join(
        _bytes(node, f"merkle_path[{index}]", length=32)
        for index, node in enumerate(merkle_path)
    )
    return bytes([leaf_version | output_parity]) + internal_key + path


def verify_taproot_control_block(
    script: bytes,
    control_block: bytes,
    output_key: bytes,
) -> bool:
    """Verify that a script and control block commit to a P2TR output key."""
    try:
        if not isinstance(script, (bytes, bytearray, memoryview)):
            return False
        script = bytes(script)
        control_block = _bytes(control_block, "control_block")
        output_key = _bytes(output_key, "output_key", length=32)
        if len(control_block) < 33 or (len(control_block) - 33) % 32:
            return False
        if len(control_block) > 33 + (128 * 32):
            return False
        control = control_block[0]
        leaf_version = control & 0xFE
        expected_parity = control & 1
        internal_key = control_block[1:33]
        merkle_root = tapleaf_hash(script, leaf_version)
        for offset in range(33, len(control_block), 32):
            merkle_root = tapbranch_hash(
                merkle_root,
                control_block[offset:offset + 32],
            )
        tweaked = taproot_tweak_pubkey(internal_key, merkle_root)
        return (
            tweaked.output_key == output_key
            and tweaked.parity == expected_parity
        )
    except (TypeError, ValueError):
        return False


def taproot_scriptpath_sign(
    message: bytes,
    private_key: bytes,
    *,
    aux_rand: Optional[bytes] = None,
    sighash_type: int = SIGHASH_DEFAULT,
) -> bytes:
    """Sign a BIP341 script-path sighash with a tapscript key."""
    return encode_taproot_signature(
        schnorr_sign(message, private_key, aux_rand=aux_rand),
        sighash_type,
    )


def taproot_scriptpath_witness(
    stack: Sequence[bytes],
    script: bytes,
    control_block: bytes,
    *,
    annex: Optional[bytes] = None,
) -> Tuple[bytes, ...]:
    """Assemble a Tapscript witness stack without interpreting its script."""
    if not isinstance(stack, Sequence):
        raise TypeError("stack must be a sequence of bytes-like items")
    if not isinstance(script, (bytes, bytearray, memoryview)):
        raise TypeError("script must be bytes-like")
    control_block = _bytes(control_block, "control_block")
    items = tuple(
        _bytes(item, f"stack[{index}]")
        for index, item in enumerate(stack)
    ) + (bytes(script), control_block)
    if annex is not None:
        annex = _bytes(annex, "annex")
        if annex[0] != 0x50:
            raise ValueError("annex must start with the Taproot annex tag 0x50")
        items += (annex,)
    return items


def taproot_tweak_pubkey(
    internal_key: bytes,
    merkle_root: bytes = b"",
) -> TaprootOutputKey:
    """Compute the BIP341 TapTweak of a 32-byte x-only internal key."""
    internal_key = _bytes(internal_key, "internal_key", length=32)
    merkle_root = _validate_merkle_root(merkle_root)
    try:
        output_point = PublicKeyXOnly(internal_key)
    except (TypeError, ValueError) as exc:
        raise ValueError("internal_key is not a valid x-only curve point") from exc
    tweak = int.from_bytes(
        tagged_hash("TapTweak", internal_key + merkle_root),
        "big",
    )
    if tweak >= CURVE_ORDER:
        raise ValueError("TapTweak is outside the secp256k1 scalar range")
    try:
        output_point.tweak_add(tweak.to_bytes(32, "big"))
    except ValueError as exc:
        raise ValueError("TapTweak produced an invalid output key") from exc
    return TaprootOutputKey(
        output_key=output_point.format(),
        parity=int(output_point.parity),
        tweak=tweak,
    )


def taproot_tweak_private_key(
    private_key: bytes,
    merkle_root: bytes = b"",
) -> Tuple[bytes, int]:
    """Return the BIP341 tweaked key-path scalar and output-key parity."""
    private_key = _private_scalar(private_key)
    private = PrivateKey(private_key)
    if private.public_key.format(compressed=True)[0] == 0x03:
        private = PrivateKey(_negate_private_scalar(private_key))
    internal_key = PublicKeyXOnly.from_secret(private_key).format()
    tweaked = taproot_tweak_pubkey(internal_key, merkle_root)
    try:
        tweaked_private = private.add(tweaked.tweak.to_bytes(32, "big"))
    except ValueError as exc:
        raise ValueError("TapTweak produced an invalid private key") from exc
    return tweaked_private.secret, tweaked.parity


def taproot_keypath_sign(
    message: bytes,
    private_key: bytes,
    *,
    merkle_root: bytes = b"",
    aux_rand: Optional[bytes] = None,
    sighash_type: int = SIGHASH_DEFAULT,
) -> bytes:
    """Sign a BIP341 key-path sighash, appending a non-default sighash byte."""
    _validate_sighash_type(sighash_type)
    tweaked_key, _ = taproot_tweak_private_key(private_key, merkle_root)
    signature = schnorr_sign(message, tweaked_key, aux_rand=aux_rand)
    return encode_taproot_signature(signature, sighash_type)


def encode_taproot_signature(signature: bytes, sighash_type: int) -> bytes:
    """Encode a 64-byte Schnorr signature with BIP341's optional sighash byte."""
    signature = _bytes(signature, "signature", length=64)
    _validate_sighash_type(sighash_type)
    return signature if sighash_type == SIGHASH_DEFAULT else signature + bytes([sighash_type])


def _validate_sighash_type(sighash_type: int) -> None:
    if not isinstance(sighash_type, int) or not 0 <= sighash_type <= 0xFF:
        raise ValueError("sighash_type must fit in one byte")
    if sighash_type & 0x7C:
        raise ValueError("sighash_type contains reserved bits")
    if (sighash_type & 0x03) == SIGHASH_DEFAULT and sighash_type != SIGHASH_DEFAULT:
        raise ValueError("SIGHASH_DEFAULT cannot be combined with ANYONECANPAY")


def _compact_size(value: int) -> bytes:
    if value < 0:
        raise ValueError("CompactSize value cannot be negative")
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + value.to_bytes(8, "little")
    raise ValueError("CompactSize value is too large")


def _script(value: bytes, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    value = bytes(value)
    return _compact_size(len(value)) + value


def _input_outpoint(transaction_input: Any) -> bytes:
    previous_tx_hash = _bytes(
        transaction_input.previous_tx_hash,
        "previous_tx_hash",
        length=32,
    )
    index = transaction_input.previous_output_index
    sequence = transaction_input.sequence
    if not isinstance(index, int) or not 0 <= index <= MAX_UINT32:
        raise ValueError("previous_output_index must fit in uint32")
    if not isinstance(sequence, int) or not 0 <= sequence <= MAX_UINT32:
        raise ValueError("sequence must fit in uint32")
    return previous_tx_hash + index.to_bytes(4, "little")


def _serialize_prevout(prevout: Any) -> bytes:
    value = prevout.value
    if not isinstance(value, int) or not 0 <= value <= 21_000_000 * 100_000_000:
        raise ValueError("prevout value is outside the Bitcoin money range")
    return value.to_bytes(8, "little") + _script(prevout.script_pubkey, "script_pubkey")


def _serialize_output(output: Any) -> bytes:
    value = output.value
    if not isinstance(value, int) or not 0 <= value <= 21_000_000 * 100_000_000:
        raise ValueError("output value is outside the Bitcoin money range")
    return value.to_bytes(8, "little") + _script(output.script_pubkey, "script_pubkey")


def taproot_sighash(
    inputs: Sequence[Any],
    outputs: Sequence[Any],
    prevouts: Sequence[Any],
    input_index: int,
    *,
    version: int = 2,
    locktime: int = 0,
    sighash_type: int = SIGHASH_DEFAULT,
    annex: Optional[bytes] = None,
    ext_flag: int = 0,
    tapleaf_hash: Optional[bytes] = None,
    key_version: int = 0,
    codeseparator_pos: int = MAX_UINT32,
) -> bytes:
    """Build the 32-byte BIP341 signature message for a transaction.

    ``prevouts`` must contain one ``TransactionOutput``-compatible object per
    input. The amount and scriptPubKey are committed by Taproot and cannot be
    omitted or inferred safely.
    """
    if not inputs or not outputs:
        raise ValueError("inputs and outputs must not be empty")
    if len(inputs) != len(prevouts):
        raise ValueError("prevouts must contain one entry per input")
    if not isinstance(input_index, int) or not 0 <= input_index < len(inputs):
        raise ValueError("input_index is outside the transaction")
    if not isinstance(version, int) or not 0 <= version <= MAX_UINT32:
        raise ValueError("version must fit in uint32")
    if not isinstance(locktime, int) or not 0 <= locktime <= MAX_UINT32:
        raise ValueError("locktime must fit in uint32")
    _validate_sighash_type(sighash_type)
    if ext_flag not in (0, 1):
        raise ValueError("ext_flag must be 0 or 1")
    if annex is not None:
        annex = _bytes(annex, "annex")
        if annex[0] != 0x50:
            raise ValueError("annex must start with the Taproot annex tag 0x50")
    if ext_flag == 1:
        tapleaf_hash = _bytes(tapleaf_hash or b"", "tapleaf_hash", length=32)
        if key_version != 0:
            raise ValueError("only Taproot key version 0 is currently supported")
        if not isinstance(codeseparator_pos, int) or not 0 <= codeseparator_pos <= MAX_UINT32:
            raise ValueError("codeseparator_pos must fit in uint32")
    elif tapleaf_hash is not None:
        raise ValueError("tapleaf_hash requires ext_flag=1")

    anyone_can_pay = bool(sighash_type & SIGHASH_ANYONECANPAY)
    base_type = sighash_type & 0x03
    spend_type = (ext_flag * 2) + (1 if annex is not None else 0)

    outpoints = b"".join(_input_outpoint(item) for item in inputs)
    amounts = b"".join(_serialize_prevout(item)[:8] for item in prevouts)
    scripts = b"".join(_script(item.script_pubkey, "script_pubkey") for item in prevouts)
    sequences = b"".join(
        item.sequence.to_bytes(4, "little") for item in inputs
    )
    serialized_outputs = b"".join(_serialize_output(item) for item in outputs)

    message = (
        bytes([sighash_type])
        + version.to_bytes(4, "little")
        + locktime.to_bytes(4, "little")
    )
    if not anyone_can_pay:
        message += _sha256(outpoints)
        message += _sha256(amounts)
        message += _sha256(scripts)
        message += _sha256(sequences)
    if base_type not in (SIGHASH_NONE, SIGHASH_SINGLE):
        message += _sha256(serialized_outputs)
    message += bytes([spend_type])

    if anyone_can_pay:
        current = inputs[input_index]
        message += _input_outpoint(current)
        message += _serialize_prevout(prevouts[input_index])
        message += current.sequence.to_bytes(4, "little")
    else:
        message += input_index.to_bytes(4, "little")

    if annex is not None:
        message += _sha256(_compact_size(len(annex)) + annex)
    if base_type == SIGHASH_SINGLE:
        if input_index >= len(outputs):
            raise ValueError("SIGHASH_SINGLE input has no corresponding output")
        message += _sha256(_serialize_output(outputs[input_index]))
    if ext_flag == 1:
        message += tapleaf_hash
        message += bytes([key_version])
        message += codeseparator_pos.to_bytes(4, "little")
    return tagged_hash("TapSighash", b"\x00" + message)


__all__ = [
    "CURVE_ORDER",
    "FIELD_ORDER",
    "SIGHASH_ALL",
    "SIGHASH_ANYONECANPAY",
    "SIGHASH_DEFAULT",
    "SIGHASH_NONE",
    "SIGHASH_SINGLE",
    "TaprootOutputKey",
    "encode_taproot_signature",
    "schnorr_sign",
    "schnorr_verify",
    "tagged_hash",
    "taproot_keypath_sign",
    "taproot_control_block",
    "taproot_scriptpath_sign",
    "taproot_scriptpath_witness",
    "taproot_sighash",
    "tapbranch_hash",
    "tapleaf_hash",
    "taproot_tweak_private_key",
    "taproot_tweak_pubkey",
    "verify_taproot_control_block",
    "xonly_public_key",
]