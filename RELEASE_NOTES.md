# Release Notes

## Version: v1.0-beta

## Summary

This beta release delivers the hybrid Bitcoin wallet migration prototype for post-quantum cryptography. The project combines a Bitcoin-compatible secp256k1 ECDSA layer with NIST-standardized ML-DSA and ML-KEM support to provide a practical migration path toward quantum-resistant wallet operations.

## Highlights

- Hybrid ECC + PQC wallet implementation via `HybridWallet`
- Deterministic Bitcoin transaction serialization helpers
- Encrypted key management for wallet persistence
- Validation suite covering wallet lifecycle, transaction signing, and benchmark thresholds
- Security review documenting current limitations and risk posture

## Included components

- `src/pqc/core.py` – ML-DSA and ML-KEM adapters using liboqs
- `src/crypto/ecdsa_module.py` – secp256k1 ECDSA support
- `src/hybrid/hybrid_wallet.py` – hybrid key generation and dual-signature verification
- `src/bitcoin/integration.py` – deterministic transaction building and fee helpers
- `src/key_management/key_store.py` – encrypted key storage
- `tests/` – unit, integration, and performance test coverage
- `docs/` – setup, architecture, security, and user guidance

## Security and compatibility notes

- The implementation intentionally fails closed if the liboqs backend is unavailable.
- Transactions are validated locally and are not broadcast to Bitcoin without an explicit node/RPC integration boundary.
- ECDSA remains for backward compatibility while the PQC layer provides quantum-resistant signatures.

## Known limitations

- Network broadcasting remains intentionally unimplemented in the core wallet library.
- PQC signatures are larger than traditional ECDSA signatures and may affect storage and transport.
- Production deployment should include additional node integration, operational hardening, and final security review.

## Target users

- Wallet researchers and developers
- Security teams evaluating hybrid migration strategies
- Engineers integrating PQC concepts into Bitcoin-compatible wallet infrastructure

## Next steps

- Complete beta validation in a controlled environment
- Extend node/RPC integration for real network submission
- Harden operational procedures and key lifecycle controls
- Finalize the stable v1.0 release after a production readiness review
