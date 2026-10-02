# Independent review checklist

This checklist scopes work for an independent cryptographic and consensus
review. It is not itself an audit or approval.

## Cryptographic implementation

- [ ] Review the coincurve/libsecp256k1 dependency, build provenance, version
  pinning, and supported deployment platforms.
- [ ] Re-run BIP340 signing/verification vectors and BIP341 wallet/control-block
  vectors on every supported platform.
- [ ] Independently validate BIP341 key- and script-path sighash bytes, including
  all sighash modes, annex, `SIGHASH_SINGLE`, and code-separator position.
- [ ] Review private-key normalization, TapTweak derivation, failure handling,
  key zeroization/custody, and nonce randomness.
- [ ] Assess timing, cache, memory, fault, and native-library side-channel risks.

## Bitcoin consensus and RPC

- [ ] Define whether PQC signatures are experimental wallet metadata or part of
  a future consensus change. Do not treat the existing hybrid envelope as a
  valid Bitcoin script.
- [ ] Run transaction construction, script-path execution, and spends against
  Bitcoin Core regtest and independent consensus test vectors.
- [ ] Review input/output validation, witness construction, fee limits, chain
  selection, cookie permissions, TLS, redirect handling, and RPC error paths.
- [ ] Test RPC behavior with wrong-chain nodes, mempool rejection, disconnects,
  stale cookie rotation, and duplicate broadcasts.
- [ ] Define confirmation tracking, replacement/cancellation, and recovery
  behavior before production use.

## Key management and PQC

- [ ] Review liboqs native build and provider configuration, ML-DSA/ML-KEM
  algorithm selection, validation, and memory handling.
- [ ] Specify and review versioned mnemonic derivation for each key family
  before claiming PQC recovery from BIP39.
- [ ] Review encrypted-store password policy, migration, backups, and recovery.

## Required report

The reviewer should record scope, exact dependency and platform versions,
reproducible commands, test vectors, findings with severity, remediation
evidence, residual risk, and an explicit production-readiness conclusion.