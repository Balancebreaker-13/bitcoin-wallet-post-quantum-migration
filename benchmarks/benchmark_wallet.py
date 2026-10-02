#!/usr/bin/env python3
"""Repeatable local microbenchmarks for wallet cryptographic operations.

Run from the repository root with:

    python bitcoin-wallet-post-quantum-migration/benchmarks/benchmark_wallet.py

Results are descriptive measurements for this machine, not security claims or
production capacity guarantees. Native liboqs must be available; the script
never substitutes mock cryptography.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.bitcoin.integration import TransactionInput, TransactionOutput  # noqa: E402
from src.bitcoin.taproot import (  # noqa: E402
    schnorr_sign,
    schnorr_verify,
    taproot_sighash,
    taproot_tweak_pubkey,
    xonly_public_key,
)
from src.crypto.ecdsa_module import ECDSAModule  # noqa: E402
from src.hybrid import HybridWallet  # noqa: E402
from src.key_management.key_store import SecureKeyStore  # noqa: E402
from src.pqc.core import DilithiumSigner, backend_available  # noqa: E402


def measure(
    name: str,
    operation: Callable[[], object],
    *,
    iterations: int,
    warmups: int,
) -> dict[str, int | float | str]:
    for _ in range(warmups):
        operation()
    samples = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        operation()
        samples.append(time.perf_counter_ns() - started)
    ordered = sorted(samples)
    p95_index = min(len(ordered) - 1, int(len(ordered) * 0.95))
    return {
        "operation": name,
        "iterations": iterations,
        "median_us": round(statistics.median(samples) / 1_000, 2),
        "p95_us": round(ordered[p95_index] / 1_000, 2),
        "min_us": round(ordered[0] / 1_000, 2),
        "max_us": round(ordered[-1] / 1_000, 2),
    }


def run(iterations: int, warmups: int) -> dict:
    if not backend_available():
        raise RuntimeError(
            "Native liboqs is unavailable; install/build the real backend before benchmarking."
        )

    pqc = DilithiumSigner(security_level=3)
    wallet = HybridWallet(pqc_signer=pqc)
    public = wallet.generate_hybrid_keypair()
    private = wallet.get_private_key(public.key_id)
    assert private is not None

    ecdsa = ECDSAModule()
    ecdsa_private, ecdsa_public = ecdsa.generate_keypair()
    schnorr_private = bytes.fromhex("00" * 31 + "03")
    schnorr_public = xonly_public_key(schnorr_private)
    message = bytes(range(32))
    aux_rand = bytes(range(32))
    schnorr_signature = schnorr_sign(message, schnorr_private, aux_rand=aux_rand)
    ecdsa_signature = ecdsa.sign(message, ecdsa_private)
    pqc_signature = pqc.sign(message, private.pqc_privkey)
    hybrid_signature = wallet.sign_transaction_hybrid(message, public.key_id)

    tx_input = TransactionInput(
        previous_tx_hash=bytes(range(32)),
        previous_output_index=0,
        script_pubkey=b"\x51",
    )
    prevout = TransactionOutput(100_000, b"\x51")
    output = TransactionOutput(90_000, b"\x51")

    with tempfile.TemporaryDirectory(prefix="wallet-bench-") as temporary:
        store = SecureKeyStore(
            "benchmark-only-password",
            str(Path(temporary) / "keys.enc.json"),
        )
        store.store_hybrid_keypair(public, private)

        operations = [
            ("ecdsa_sign", lambda: ecdsa.sign(message, ecdsa_private)),
            ("ecdsa_verify", lambda: ecdsa.verify(message, ecdsa_signature, ecdsa_public)),
            ("bip340_sign", lambda: schnorr_sign(message, schnorr_private, aux_rand=aux_rand)),
            ("bip340_verify", lambda: schnorr_verify(message, schnorr_signature, schnorr_public)),
            ("taproot_tweak_pubkey", lambda: taproot_tweak_pubkey(schnorr_public)),
            (
                "bip341_sighash",
                lambda: taproot_sighash([tx_input], [output], [prevout], 0),
            ),
            ("ml_dsa_sign", lambda: pqc.sign(message, private.pqc_privkey)),
            (
                "ml_dsa_verify",
                lambda: pqc.verify(message, pqc_signature, public.pqc_pubkey),
            ),
            ("hybrid_sign", lambda: wallet.sign_transaction_hybrid(message, public.key_id)),
            (
                "hybrid_verify",
                lambda: wallet.verify_transaction_hybrid(
                    message,
                    hybrid_signature,
                    public,
                ),
            ),
            ("key_store_encrypt_write", lambda: store.store_hybrid_keypair(public, private)),
            ("key_store_decrypt_read", lambda: store.retrieve_hybrid_key(public.key_id)),
        ]
        results = [
            measure(name, operation, iterations=iterations, warmups=warmups)
            for name, operation in operations
        ]

    keygen_samples = max(1, min(iterations, 3))
    results.append(
        measure(
            "ml_dsa_keygen",
            pqc.generate_keypair,
            iterations=keygen_samples,
            warmups=0,
        )
    )
    return {
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "pqc_algorithm": pqc.algorithm_name,
            "pqc_backend_available": True,
        },
        "results": results,
        "notes": [
            "Microbenchmarks are not a side-channel assessment.",
            "Key-store write measurements include encryption, fsync, and atomic replacement.",
            "Hybrid verification includes both ECDSA and ML-DSA verification.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.iterations < 1 or args.warmups < 0:
        parser.error("iterations must be positive and warmups must be non-negative")
    result = run(args.iterations, args.warmups)
    encoded = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)


if __name__ == "__main__":
    main()