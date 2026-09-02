# Bitcoin Integration API

## Overview

The Bitcoin integration module provides deterministic transaction serialization and hybrid signature support for Bitcoin wallets using post-quantum cryptography.

## Module Structure

```python
from src.bitcoin.integration import (
    BitcoinTransactionBuilder,
    TransactionInput,
    TransactionOutput,
    encode_compact_size,
)
```

## Transaction Data Structures

### TransactionInput

Represents a Bitcoin transaction input.

```python
from src.bitcoin.integration import TransactionInput

input = TransactionInput(
    previous_tx_hash=bytes(32),      # Previous tx hash (32 bytes)
    previous_output_index=0,         # Output index (uint32)
    script_pubkey=b"\x51",          # Script bytes
    sequence=0xFFFFFFFF,            # Sequence number (uint32, default max)
    witness=()                       # Witness stack for SegWit (optional)
)

# All values are validated on instantiation
assert len(input.previous_tx_hash) == 32
assert 0 <= input.previous_output_index <= 0xFFFFFFFF
assert 0 <= input.sequence <= 0xFFFFFFFF
```

### TransactionOutput

Represents a Bitcoin transaction output.

```python
from src.bitcoin.integration import TransactionOutput

output = TransactionOutput(
    value=50_000,              # Satoshis (uint64)
    script_pubkey=b"\x51"    # Script bytes
)

# Value is validated
assert 0 <= output.value <= 21_000_000 * 100_000_000  # Max Bitcoin supply
```

## BitcoinTransactionBuilder

Main class for building and signing Bitcoin transactions.

### Initialization

```python
from src.bitcoin.integration import BitcoinTransactionBuilder
from src.hybrid import HybridWallet

# Without wallet (for unsigned transactions)
builder = BitcoinTransactionBuilder()

# With hybrid wallet (for signing)
wallet = HybridWallet()
builder = BitcoinTransactionBuilder(wallet)

print(builder.version)    # 2 (default)
print(builder.locktime)   # 0 (default)
```

### Transaction Creation

#### Legacy Transaction

```python
from src.bitcoin.integration import TransactionInput, TransactionOutput

inputs = [
    TransactionInput(
        previous_tx_hash=bytes(32),
        previous_output_index=0,
        script_pubkey=b"\x51"
    )
]

outputs = [
    TransactionOutput(value=50_000, script_pubkey=b"\x51"),
    TransactionOutput(value=30_000, script_pubkey=b"\x51")
]

tx_bytes = builder.create_transaction(
    inputs=inputs,
    outputs=outputs,
    tx_type="legacy"
)
```

#### SegWit Transaction

```python
inputs = [
    TransactionInput(
        previous_tx_hash=bytes(32),
        previous_output_index=0,
        script_pubkey=b"\x51",
        witness=(b"signature", b"pubkey")  # Witness stack
    )
]

tx_bytes = builder.create_transaction(
    inputs=inputs,
    outputs=outputs,
    tx_type="segwit"
)
```

#### Taproot Transaction

```python
tx_bytes = builder.create_transaction(
    inputs=inputs,
    outputs=outputs,
    tx_type="taproot"
)
```

### Script Helpers

#### Pay-to-Public-Key-Hash (P2PKH)

```python
pubkey_hash = bytes(20)  # RIPEMD160(SHA256(pubkey))
script = builder.create_p2pkh_script(pubkey_hash)

# Output: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
assert len(script) == 25
```

#### Pay-to-Witness-Public-Key-Hash (P2WPKH)

```python
pubkey_hash = bytes(20)
script = builder.create_p2wpkh_script(pubkey_hash)

# Output: OP_0 <pubkey_hash>
assert len(script) == 22
```

#### Pay-to-Taproot (P2TR)

```python
taproot_key = bytes(32)  # Taproot output key
script = builder.create_p2tr_script(taproot_key)

# Output: OP_1 <taproot_key>
assert len(script) == 34
```

### Transaction Signing

```python
tx_bytes = builder.create_transaction(inputs, outputs)

# Generate hybrid signature
signature = builder.sign_transaction(tx_bytes, key_id)

# Signature is a hybrid ML-DSA + ECDSA signature
assert len(signature) > 3000  # Approximate size
```

### Signature Verification

```python
# Verify transaction signature
is_valid = builder.verify_transaction_signature(
    tx_bytes,
    signature,
    key_id
)

assert isinstance(is_valid, bool)
```

### Transaction Analysis

#### Get Transaction Digest

```python
# Double SHA256 hash for signing
digest = BitcoinTransactionBuilder.transaction_digest(tx_bytes)

assert len(digest) == 32
```

#### Get Transaction ID

```python
# Display-format TXID (reversed digest hex)
txid = BitcoinTransactionBuilder.transaction_id(tx_bytes)

assert isinstance(txid, str)
assert len(txid) == 64  # Hex encoded 32 bytes
```

#### Estimate Transaction Size

```python
size = builder.estimate_transaction_size(
    num_inputs=2,
    num_outputs=3,
    tx_type="legacy"
)

# Returns: int (bytes)
# Note: Hybrid signatures will significantly increase actual size
```

#### Calculate Transaction Fee

```python
# Calculate fee for given satoshis-per-byte rate
fee = builder.calculate_transaction_fee(
    num_inputs=2,
    num_outputs=3,
    fee_rate=5,  # satoshis per byte
    tx_type="legacy"
)

# Returns: int (satoshis)
```

### Network Broadcasting

```python
try:
    txid = builder.broadcast_transaction(signed_tx_bytes)
except NotImplementedError:
    print("Broadcasting requires node/RPC integration")
```

## Utility Functions

### Compact Size Encoding

Bitcoin uses variable-length CompactSize for efficient encoding.

```python
from src.bitcoin.integration import encode_compact_size

# Small values
assert encode_compact_size(252) == b"\xfc"

# 1-byte length prefix
assert encode_compact_size(253) == b"\xfd\xfd\x00"

# 2-byte length prefix
assert encode_compact_size(65_536) == b"\xfe\x00\x00\x01\x00"

# 4-byte length prefix (up to 4GB)
assert encode_compact_size(4_294_967_296) == b"\xff\x00\x00\x00\x00\x01\x00\x00\x00"
```

## Error Handling

```python
try:
    # Invalid input count
    builder.create_transaction([], outputs)
except ValueError:
    print("Transaction must have inputs and outputs")

try:
    # Invalid value
    TransactionOutput(value=-1, script_pubkey=b"")
except ValueError:
    print("Value must be non-negative")

try:
    # Invalid hash length
    builder.create_p2pkh_script(bytes(19))
except ValueError:
    print("Hash must be exactly 20 bytes")

try:
    # No wallet configured
    builder.sign_transaction(tx_bytes, key_id)
except RuntimeError:
    print("Wallet not initialized")
```

## Usage Examples

### Complete Transaction Workflow

```python
from src.bitcoin.integration import (
    BitcoinTransactionBuilder,
    TransactionInput,
    TransactionOutput,
)
from src.hybrid import HybridWallet

# Setup
wallet = HybridWallet()
public_key = wallet.generate_hybrid_keypair()
builder = BitcoinTransactionBuilder(wallet)

# Create transaction
inputs = [TransactionInput(
    previous_tx_hash=bytes(32),
    previous_output_index=0,
    script_pubkey=b"\x51"
)]
outputs = [TransactionOutput(
    value=50_000,
    script_pubkey=builder.create_p2pkh_script(bytes(20))
)]

tx_bytes = builder.create_transaction(inputs, outputs, tx_type="legacy")
print(f"Unsigned tx size: {len(tx_bytes)} bytes")

# Sign transaction
signature = builder.sign_transaction(tx_bytes, public_key.key_id)
print(f"Signature size: {len(signature)} bytes")

# Verify signature
is_valid = builder.verify_transaction_signature(
    tx_bytes,
    signature,
    public_key.key_id
)
print(f"Valid: {is_valid}")

# Get TXID
txid = builder.transaction_id(tx_bytes)
print(f"TXID: {txid}")
```

### Fee Estimation

```python
# Estimate fee for typical transaction
size = builder.estimate_transaction_size(
    num_inputs=1,
    num_outputs=2,
    tx_type="legacy"
)

fee_rate = 10  # satoshis per byte
fee = size * fee_rate

print(f"Estimated size: {size} bytes")
print(f"Estimated fee: {fee} satoshis")

# Note: Hybrid signatures will add ~3400 bytes
```

## Constants

```python
MAX_MONEY = 21_000_000 * 100_000_000      # 2.1e15 satoshis
MAX_UINT32 = 0xFFFFFFFF                   # 4294967295
MAX_UINT64 = 0xFFFFFFFFFFFFFFFF          # 18446744073709551615

# Bitcoin opcodes
OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xAC
```

## References

- [Bitcoin Protocol Reference](https://developer.bitcoin.org/reference/)
- [BIP141: Segregated Witness](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
- [BIP340: Schnorr Signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [BIP341: Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
