# Bitcoin Wallet Post-Quantum Migration

A research and prototyping project for exploring Bitcoin-compatible wallet primitives alongside post-quantum cryptography.

Status: research prototype and engineering validation project. It is not production-ready, not suitable for handling real funds, and does not provide a consensus-valid Bitcoin mainnet spending system.

## Implemented

- secp256k1 ECDSA and BIP340 Schnorr-related wallet primitives
- BIP341 Taproot helpers including tweak, sighash, and control-block logic
- hybrid wallet envelope with ECC + PQC signing in a versioned format
- encrypted key storage with validation and recovery-oriented flows
- Bitcoin Core RPC integration patterns with chain and mempool checks before broadcast
- deterministic transaction serialization helpers
- Python test suite covering core cryptography, hybrid wallet behavior, integration, and key management
- benchmark harness for wallet, crypto, and encrypted key-store performance measurement

## Current project maturity

The project has completed substantial implementation and validation work, but it remains in a research/engineering stage rather than a release-ready state.

The repository itself documents the current reality:

- Latest local validation: 55 tests passed, 1 skipped
- Latest coverage: approximately 80% statement coverage on Python 3.13.11
- Benchmark harness exists and is repeatable in a configured environment
- Live Bitcoin Core regtest validation has not been completed
- A representative deployment-hardware benchmark run has not been completed
- Independent cryptographic, consensus, and side-channel review remain open

This project is therefore suitable for research, validation, and integration prototyping, but not for beta or production deployment.

## Release-gate phase

The current phase is validation hardening and release-gate preparation.

The next required work is:

1. live Bitcoin Core regtest validation in a configured environment
2. authoritative BIP340/BIP341/BIP342 vector verification
3. native liboqs backend validation on representative hardware
4. independent cryptographic and consensus review
5. final release-gate sign-off before any beta or production claim

See [`ROADMAP.md`](ROADMAP.md) and [`docs/release_gate_checklist.md`](docs/release_gate_checklist.md) for the next validation gates and sign-off checklist.

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

## Important caveats

- no live regtest validation against a configured Bitcoin Core node
- no authoritative BIP341 sighash vector cross-check yet
- no full Tapscript/consensus-valid script execution layer
- no independent security review for side-channel, cryptographic, or consensus concerns
- no deployment-grade benchmarking or hardware validation

This project is intentionally careful about the boundary between prototype work and production readiness.
