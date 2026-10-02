# Wallet performance benchmarks

Run from the project root:

```sh
python bitcoin-wallet-post-quantum-migration/benchmarks/benchmark_wallet.py
```

Use `--iterations`, `--warmups`, and `--output report.json` to control or save a
run. The harness measures secp256k1 ECDSA, BIP340 signing and verification,
Taproot tweaks and BIP341 sighashes, native ML-DSA, hybrid signing and
verification, and encrypted key-store reads and writes. It requires the real
native liboqs backend and fails explicitly when it is unavailable.

Results are local microbenchmarks, not cross-machine comparisons, service-level
objectives, side-channel tests, or a production-readiness assessment. Record the
machine, Python version, dependency versions, and operating conditions when
comparing runs.