# Phase 4 Validation Status

**Status: core test work completed; release and production validation remain
open.**

## Verified

- Latest full local test run: 55 passed, 1 skipped.
- Latest measured statement coverage: 80% on Python 3.13.11.
- Bitcoin Core RPC request and broadcast checks have mocked-node tests.
- A repeatable wallet cryptography and key-store benchmark harness is present.

## Still open

- The skipped test requires the native liboqs backend, which was unavailable in
  the latest environment.
- The benchmark harness could not produce a representative run because its
  native backend build did not complete; deployment-hardware results are not
  available.
- No live Bitcoin Core regtest validation has been performed.
- Taproot sighash handling still needs comparison against an authoritative
  BIP341 sighash vector.
- No independent cryptographic, consensus, or side-channel review has been
  completed.

These results do not establish beta or production readiness. See
[`ROADMAP.md`](ROADMAP.md) and
[`docs/security/audit_report.md`](docs/security/audit_report.md) for the
remaining release gates.