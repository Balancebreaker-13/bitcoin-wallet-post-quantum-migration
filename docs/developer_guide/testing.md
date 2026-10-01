# Testing Guide

The project includes unit, integration, and performance tests covering the hybrid wallet flow.

## Run the full suite

```bash
pytest -q
```

## Focused suites

```bash
pytest tests/test_pqc_core.py -q
pytest tests/test_hybrid_wallet.py -q
pytest tests/test_bitcoin_integration.py -q
pytest tests/test_integration.py -q
pytest tests/test_performance.py -q
```

## What is covered

- PQC backend availability and validation
- Signature creation and verification
- Hybrid wallet serialization and recovery
- Bitcoin transaction building and hashing
- Key storage and retrieval workflows
- Performance thresholds for critical operations

## Notes

- Some tests are skipped automatically if the liboqs backend is unavailable.
- Performance tests are intended to catch regressions, not enforce exact runtime numbers on every machine.
- Always prefer testing the exact behavior touched by your change.

## Useful pytest flags

```bash
pytest -q -k hybrid
pytest -q --maxfail=1
pytest -q --cov=src --cov-report=term-missing
```
