# Bitcoin and Taproot integration

This API exposes Bitcoin wire serialization, BIP340 Schnorr operations, BIP341
Taproot key and script-path primitives, and an opt-in Bitcoin Core RPC client.
Curve operations use the `coincurve` binding to libsecp256k1. Transaction and
key policy is still the caller's responsibility.

## Key-path signing

Build a BIP341 sighash from the complete transaction and every input's previous
output amount and script. The sighash commits to input/output data, version,
locktime, spend type, and the selected hash mode.

```python
from src.bitcoin import (
    TransactionInput,
    TransactionOutput,
    taproot_keypath_sign,
    taproot_sighash,
)

inputs = [TransactionInput(
    previous_tx_hash=bytes.fromhex("00" * 32),  # wire-order hash
    previous_output_index=0,
    script_pubkey=b"\x51",  # spent output's locking script; not scriptSig
)]
prevouts = [TransactionOutput(100_000, b"\x51")]
outputs = [TransactionOutput(90_000, b"\x51")]

digest = taproot_sighash(inputs, outputs, prevouts, input_index=0)
signature = taproot_keypath_sign(digest, internal_private_key)
```

Supply real previous-output data from a trusted source; never guess an amount
or script. Use the full 64-byte signature for `SIGHASH_DEFAULT`; non-default
sighash modes append their one-byte flag.

## Script-path primitives

`tapleaf_hash`, `tapbranch_hash`, `taproot_tweak_pubkey`,
`taproot_control_block`, and `verify_taproot_control_block` support building
and checking Taproot commitments. `taproot_sighash(..., ext_flag=1,
tapleaf_hash=...)` builds the script-path sighash. `taproot_scriptpath_sign`
signs that digest with a tapscript key, and `taproot_scriptpath_witness`
assembles stack items, script, control block, and optional annex.

This package does **not** execute Tapscript or validate every consensus and
policy rule. Use a maintained Bitcoin consensus implementation for script
execution and transaction validation.

## Bitcoin Core RPC

Broadcasting is explicit and requires a local cookie file, expected chain, and
a raw signed transaction accepted by the node's mempool:

```python
from src.bitcoin import BitcoinCoreRpcClient

client = BitcoinCoreRpcClient(
    "http://127.0.0.1:18443",
    "/path/to/regtest/.cookie",
    expected_chain="regtest",
)
txid = client.broadcast_transaction(raw_consensus_valid_transaction)
```

Plain HTTP is restricted to loopback. Remote endpoints must use HTTPS with
certificate verification. The RPC client checks `getblockchaininfo`,
`testmempoolaccept`, then `sendrawtransaction`. It does not track confirmations
or make a hybrid ML-DSA envelope consensus-valid. No live-node/regtest test has
been performed yet.

## Security boundary

Do not use these primitives for mainnet funds until the hybrid-to-Bitcoin
consensus migration is specified, a live regtest flow passes, and independent
cryptographic, consensus, and side-channel reviews are complete.