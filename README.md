# WISDOM NETWORK WALLET

A research and prototyping project focused on secure digital wallet migration strategies in a post-quantum cryptography environment. The repository explores hybrid cryptographic patterns that combine legacy ECC protections with quantum-resistant signing and key management workflows.

Status: research prototype and engineering validation project. It is not production-ready, not suitable for handling real funds, and does not provide a consensus-valid wallet spending system.

## What is implemented

- secp256k1 ECDSA and BIP340 Schnorr-style wallet primitives
- BIP341-style Taproot support primitives, including key tweaks and sighash helpers
- hybrid wallet envelope with ECC + PQC signing in a versioned format
- encrypted key storage with validation and recovery-oriented flows
- Bitcoin Core RPC integration patterns with chain and mempool checks before broadcast
- deterministic transaction serialization helpers
- Python test suite covering core cryptography, hybrid wallet behavior, integration, and key management
- benchmark harness for wallet, crypto, and encrypted key-store performance measurement

## Current project maturity

The project has completed a substantial implementation and validation cycle, but it remains in a research/engineering stage rather than a release-ready state.

The repository itself documents the present reality:

- Latest local validation: 55 tests passed, 1 skipped
- Latest coverage: approximately 80% statement coverage on Python 3.13.11
- Benchmark harness exists and is repeatable in a configured environment
- Live Bitcoin Core regtest validation has not been completed
- A representative deployment-hardware benchmark run has not been completed
- Independent cryptographic, consensus, and side-channel review remain open

This project is therefore suitable for research, validation, and integration prototyping, but not for beta or production deployment.

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

The project loads the native `oqs` backend and wraps the relevant Post-Quantum algorithms for the wallet. The implementation explicitly rejects missing or unusable native PQC backends instead of silently degrading.

### Hybrid wallet model

The hybrid wallet signs message or transaction data with both the legacy ECC key and the PQC signature key, then encodes them in a versioned bundle. Verification requires both signature components to be present and valid.

This is useful as a transitional architecture and migration pattern, but it is not a consensus-valid Bitcoin script or a production wallet signing policy.

### Bitcoin integration

The repository includes:

- transaction serialization helpers
- BIP340/BIP341-related key tweak and sighash helpers
- RPC integration patterns for Bitcoin Core
- secure-cookie authentication and mempool/chain validation checks before broadcast

These are engineering validation components, not a full consensus-ready Bitcoin implementation.

## Important caveats

The project is intentionally careful about the boundary between prototype work and production readiness. Key caveats from the repo include:

- no live regtest validation against a configured Bitcoin Core node
- no authoritative BIP341 sighash vector cross-check yet
- no full Tapscript/consensus-valid script execution layer
- no independent security review for side-channel, cryptographic, or consensus concerns
- no deployment-grade benchmarking or hardware validation

## Development

Run the test suite from the repository root:

```bash
python -m pytest -q tests
```

Optional coverage run:

```bash
python -m pytest --cov=src --cov-report=term-missing -q tests
```

Run the benchmarking harness after confirming the native liboqs backend is available:

```bash
python benchmarks/benchmark_wallet.py
```

## Next phase objective

The current phase is validation hardening and transition-readiness work. The primary goals are:

1. run and record representative validation results in a configured environment
2. complete live Bitcoin Core regtest validation where supported
3. verify Taproot and sighash logic against authoritative vectors
4. strengthen documentation around security and deployment boundaries
5. prepare the project for a disciplined next release gate instead of claiming production readiness

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

This repository is best described as a cryptographic migration prototype and validation project. It is valuable for research, implementation experiments, and careful engineering evaluation, but it is not a production wallet or a deployment-ready digital asset platform.
