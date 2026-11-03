# WISDOM NETWORK WALLET

A research and prototyping project focused on secure digital-wallet migration strategies for a post-quantum cryptography environment.

This repository explores hybrid cryptographic patterns combining secp256k1 ECDSA with ML-DSA / ML-KEM-style PQC interfaces, transaction serialization helpers, encrypted key storage, and validation-oriented wallet logic.

Status: research prototype and engineering-validation project.

This project is not production-ready, is not suitable for handling real funds, and does not provide a consensus-valid Bitcoin spending system. It is meant for research, validation, and implementation experimentation until the required release and security gates are passed.

## What is implemented

- secp256k1 ECDSA and BIP340/BIP341-style Taproot primitives
- hybrid wallet envelope with ECC + PQC signing in a versioned format
- encrypted key storage with validation and recovery-oriented flows
- Bitcoin Core RPC integration patterns with chain and mempool checks before broadcast
- deterministic transaction serialization helpers
- Python test suite covering core cryptography, hybrid wallet behavior, integration, and key management
- benchmark harness for wallet, crypto, and encrypted key-store performance measurement

## Current project maturity

The project contains substantial implementation work and validation artifacts, but it remains in a research / engineering-validation stage rather than a release-ready state.

The repository documents the current reality:

- local validation exists and the historical run reported 55 passed / 1 skipped
- measured statement coverage was approximately 80% on Python 3.13.11
- a benchmark harness exists and is repeatable in a configured environment
- live Bitcoin Core regtest validation has not been completed
- representative deployment-hardware benchmark validation has not been completed
- independent cryptographic, consensus, and side-channel review remain open

This project is therefore suitable for research, validation, and integration prototyping, but it is not suitable for beta or production deployment.

## Repository structure

- `src/crypto/` — core cryptographic adapters and algorithm wrappers
- `src/pqc/` — ML-DSA / ML-KEM compatibility layer using liboqs
- `src/hybrid/` — hybrid ECC + PQC wallet implementation
- `src/bitcoin/` — transaction building, Taproot helpers, and RPC integration
- `src/key_management/` — encrypted key storage and recovery tooling
- `tests/` — unit and integration coverage
- `benchmarks/` — repeatable local benchmarking harness
- `poc/` — proof-of-concept demos
- `docs/` — security, research, design, developer, and user documentation

## Key technical components

### PQC adapters

The project loads the native `oqs` backend and wraps the relevant post-quantum algorithms for the wallet. The implementation explicitly fails closed when the native backend is missing instead of silently falling back to insecure primitives.

### Hybrid wallet model

The hybrid wallet signs transaction or message data with both the legacy ECC key and the PQC signing key, then encodes them as a versioned bundle. Verification requires both components to validate.

This design is useful for transition, migration, and validation work, but it is not a consensus-valid Bitcoin script or a production wallet signing policy.

### Bitcoin integration

The repository includes:

- transaction serialization helpers
- BIP340/BIP341-related key tweak and sighash helpers
- RPC integration patterns for Bitcoin Core
- secure-cookie authentication and mempool/chain validation checks before broadcast

These are engineering-validation components, not a full consensus-ready Bitcoin implementation.

## Important caveats

The project is intentionally careful about the boundary between prototype work and production readiness. Key caveats include:

- no live regtest validation against a configured Bitcoin Core node
- no authoritative BIP341 sighash-vector cross-check yet
- no full Tapscript or consensus-valid execution layer
- no independent cryptographic, consensus, or side-channel review
- no deployment-grade benchmarking or hardware validation
- BIP32 / HD wallet derivation is not implemented unless a separate design decision is approved and validated

## Development

Run the test suite from the repository root:

```bash
python -m pytest -q tests
```

Optional coverage run:

```bash
python -m pytest --cov=src --cov-report=term-missing -q tests
```

Run the benchmarking harness only after confirming the native liboqs backend is available:

```bash
python benchmarks/benchmark_wallet.py
```

## Next phase objective

The current phase is validation hardening and transition-readiness work. The primary goals are:

1. confirm that the project installs and tests in a reproducible environment
2. complete live Bitcoin Core regtest validation where supported
3. verify Taproot and sighash logic against authoritative vectors
4. strengthen documentation around security and deployment boundaries
5. prepare the project for disciplined next-stage release-gate work rather than claiming production readiness

## Related documentation

- `ROADMAP.md` — roadmap and phase status
- `PHASE3_COMPLETION_SUMMARY.md` — core implementation summary
- `PHASE4_COMPLETION_SUMMARY.md` — validation and remaining open gates
- `docs/security/audit_report.md` — security review findings
- `docs/INSTALLATION.md` — setup guidance
- `docs/api/` — API-oriented documentation
- `docs/user_guide/` — user workflows and wallet usage
- `CONTRIBUTING.md` — contribution expectations

## License

This project is licensed under the Apache License 2.0. See `LICENSE` for details.

## Status summary

This repository is best described as a cryptographic migration prototype and validation project. It is valuable for research, implementation experiments, and careful engineering evaluation, but it is not a mature wallet for real funds or a production-ready Bitcoin deployment.
