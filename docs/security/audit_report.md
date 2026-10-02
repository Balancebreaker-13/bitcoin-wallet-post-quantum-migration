# Security Review Report

**Review scope:** the current local cryptography, hybrid-wallet, transaction
serialization, and encrypted key-storage implementation.

**Review type:** focused engineering security review. This is not a formal
third-party cryptographic certification, consensus review, or side-channel
assessment.

## Executive summary

The implementation fails closed when the native `liboqs` backend is not
available, uses real secp256k1 ECDSA instead of placeholder signatures, and
protects persisted private material with per-store salted Scrypt and Fernet
encryption. Malformed signatures, key documents, passwords, and transaction
fields are rejected or return an invalid result without silently accepting
unsafe input.

The project is **not ready for mainnet transaction broadcasting**. BIP340 and
BIP341 primitives now use coincurve/libsecp256k1, and an opt-in Bitcoin Core
RPC client is available. The client is covered by mocked-node tests only; it
has not been tested against a live regtest node. The hybrid ML-DSA envelope is
still not a Bitcoin consensus script, and this project does not execute
Tapscript. Mainnet use remains explicitly out of scope pending a consensus
migration design, live node testing, and independent review.

## Controls reviewed

### Cryptography

- ML-DSA/ML-KEM operations use the native `liboqs` provider and validate
  algorithm names, key sizes, and operation inputs.
- ECDSA uses the `cryptography` secp256k1 implementation with DER signatures
- BIP340 Schnorr, BIP341 key tweaks, leaf/branch hashes, control-block
  verification, sighashes, and witness helpers use coincurve/libsecp256k1 for
  curve operations. Published BIP340 signing vectors and BIP341 wallet
  key-tweak/control-block vectors are covered. Sighash and witness behavior has
  unit coverage but has not yet been cross-checked against an authoritative
  BIP341 sighash vector.
- The Python package binding reduces custom curve-arithmetic risk but does not
  constitute a third-party audit of libsecp256k1 integration or this wallet.
- Hybrid signatures include a versioned envelope containing both component
  signatures and are verified against the exact transaction digest.
- No random-byte cryptographic fallback is present.

### Key storage

- Each store has an independent random salt.
- Password-derived encryption keys use Scrypt and Fernet authenticated
  encryption.
- Writes use a temporary file, flush/fsync, atomic replacement, and restrictive
  owner-only permissions.
- Private fields are not included in public-key exports or plaintext store
  documents.
- Wrong passwords, malformed records, tampered ciphertext, duplicate IDs, and
  mismatched key pairs fail safely.

### Recovery

- Mnemonics use the complete standard English BIP39 word list.
- 12-word and 24-word entropy sizes are validated and checksums are checked.
- BIP39 seed derivation delegates to the maintained `mnemonic` implementation.
- Generated phrases are returned to the caller and are not persisted by the
  key store.
- Deterministic derivation of PQC key hierarchies from a mnemonic is not
  implied; adding it requires a separately specified protocol.

### Transaction boundary

- CompactSize encoding and transaction fields have explicit range checks.
- Transaction IDs are calculated locally from serialized transaction bytes.
- Bitcoin Core RPC uses cookie-file authentication, loopback-only plaintext
  HTTP, TLS for remote endpoints, an explicit expected chain, and a mempool
  acceptance check before broadcasting.
- RPC behavior has only been tested with mocked responses; no configured
  regtest node was available for live integration testing.
- Input serialization keeps the spent output's `script_pubkey` separate from
  the input's unlocking `script_sig`.

## Findings and disposition

| ID | Finding | Severity | Disposition |
| --- | --- | --- | --- |
| F-01 | Hybrid signature bytes are not currently a Bitcoin consensus script | Critical for mainnet use | Open; requires a consensus-compatible migration design |
| F-02 | The new libsecp256k1 binding has not received an independent integration or side-channel audit | High | Open; independent review required before production signing |
| F-03 | Bitcoin Core RPC has only mocked-node coverage; no live regtest or confirmation workflow is verified | High | Open; validate against regtest and add confirmation/status handling |
| F-04 | PQC key hierarchy derivation from BIP39 is unspecified | High | Open by design; define derivation domains and recovery semantics first |
| F-05 | No formal constant-time or side-channel audit has been performed | Medium | Open; review native/provider behavior and deployment environment |
| F-07 | Tapscript is not interpreted by this project | High | Open; use an established consensus implementation or complete independent validation before spending script-path outputs |
| F-06 | The local review found no plaintext private-key persistence path in the covered store flow | Informational | Covered by tests; retain regression tests |

## Required gates before network use

1. Define a Bitcoin consensus-compatible output and signature migration
   protocol.
2. Independently review the coincurve/libsecp256k1 integration and validate
   signing behavior in the supported deployment environment.
3. Test the authenticated RPC client against a regtest node and add transaction
   confirmation/status handling.
4. Specify mnemonic-to-key recovery for every key type, including domain
   separation and versioning.
5. Obtain a formal cryptographic and side-channel review before production
   deployment.
6. Do not represent the hybrid ML-DSA envelope as a Bitcoin consensus
   authorization mechanism until a soft-fork or other consensus-compatible
   protocol is specified and validated.
