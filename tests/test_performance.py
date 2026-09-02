"""Performance benchmarking for hybrid wallet operations."""

import time
import pytest
from src.hybrid import HybridWallet
from src.bitcoin.integration import (
    BitcoinTransactionBuilder,
    TransactionInput,
    TransactionOutput,
)
from src.pqc.core import DilithiumSigner, KyberKEM, backend_available


class TestPerformanceBenchmarks:
    """Performance benchmarks for critical operations."""

    @pytest.mark.skipif(not backend_available(), reason="liboqs not available")
    def test_keypair_generation_performance(self):
        """Benchmark keypair generation performance."""
        signer = DilithiumSigner(security_level=3)
        kem = KyberKEM(security_level=768)

        # Dilithium keypair generation
        start = time.time()
        for _ in range(10):
            signer.generate_keypair()
        dil_time = (time.time() - start) / 10

        # Kyber keypair generation
        start = time.time()
        for _ in range(10):
            kem.generate_keypair()
        kyb_time = (time.time() - start) / 10

        print(f"Dilithium keypair: {dil_time*1000:.2f}ms")
        print(f"Kyber keypair: {kyb_time*1000:.2f}ms")

        # Should complete in reasonable time
        assert dil_time < 0.1  # 100ms
        assert kyb_time < 0.05  # 50ms

    @pytest.mark.skipif(not backend_available(), reason="liboqs not available")
    def test_signing_performance(self):
        """Benchmark signing performance."""
        signer = DilithiumSigner(security_level=3)
        pub_key, priv_key = signer.generate_keypair()
        message = b"test message" * 100

        # Dilithium signing
        start = time.time()
        for _ in range(10):
            signer.sign(message, priv_key)
        sign_time = (time.time() - start) / 10

        print(f"Dilithium signing: {sign_time*1000:.2f}ms")
        assert sign_time < 0.01  # 10ms

    @pytest.mark.skipif(not backend_available(), reason="liboqs not available")
    def test_verification_performance(self):
        """Benchmark verification performance."""
        signer = DilithiumSigner(security_level=3)
        pub_key, priv_key = signer.generate_keypair()
        message = b"test message" * 100
        signature = signer.sign(message, priv_key)

        # Dilithium verification
        start = time.time()
        for _ in range(10):
            signer.verify(message, signature, pub_key)
        verify_time = (time.time() - start) / 10

        print(f"Dilithium verification: {verify_time*1000:.2f}ms")
        assert verify_time < 0.01  # 10ms

    @pytest.mark.skipif(not backend_available(), reason="liboqs not available")
    def test_hybrid_wallet_signing_performance(self):
        """Benchmark hybrid wallet transaction signing."""
        wallet = HybridWallet()
        public_key = wallet.generate_hybrid_keypair()
        tx_data = b"transaction data" * 50

        # Hybrid signing
        start = time.time()
        for _ in range(5):
            wallet.sign_transaction_hybrid(tx_data, public_key.key_id)
        sign_time = (time.time() - start) / 5

        print(f"Hybrid wallet signing: {sign_time*1000:.2f}ms")
        assert sign_time < 0.05  # 50ms

    @pytest.mark.skipif(not backend_available(), reason="liboqs not available")
    def test_hybrid_wallet_verification_performance(self):
        """Benchmark hybrid wallet signature verification."""
        wallet = HybridWallet()
        public_key = wallet.generate_hybrid_keypair()
        tx_data = b"transaction data" * 50
        signature = wallet.sign_transaction_hybrid(tx_data, public_key.key_id)

        # Hybrid verification
        start = time.time()
        for _ in range(5):
            wallet.verify_transaction_hybrid(tx_data, signature, public_key)
        verify_time = (time.time() - start) / 5

        print(f"Hybrid wallet verification: {verify_time*1000:.2f}ms")
        assert verify_time < 0.05  # 50ms

    @pytest.mark.skipif(not backend_available(), reason="liboqs not available")
    def test_transaction_building_performance(self):
        """Benchmark transaction building performance."""
        builder = BitcoinTransactionBuilder()

        # Build transactions
        start = time.time()
        for i in range(20):
            builder.create_transaction(
                [
                    TransactionInput(
                        previous_tx_hash=bytes(32),
                        previous_output_index=i,
                        script_pubkey=b"\x51",
                    )
                ],
                [
                    TransactionOutput(
                        value=50_000 + i * 1000, script_pubkey=b"\x51"
                    )
                ],
            )
        build_time = (time.time() - start) / 20

        print(f"Transaction building: {build_time*1000:.2f}ms")
        assert build_time < 0.01  # 10ms

    @pytest.mark.skipif(not backend_available(), reason="liboqs not available")
    def test_key_size_analysis(self):
        """Analyze key and signature sizes."""
        signer = DilithiumSigner(security_level=3)
        kem = KyberKEM(security_level=768)

        pub_key, priv_key = signer.generate_keypair()
        kem_pub, kem_priv = kem.generate_keypair()
        message = b"test" * 100
        signature = signer.sign(message, priv_key)

        print(f"\nKey Size Analysis:")
        print(f"  ML-DSA-65 public key: {len(pub_key)} bytes")
        print(f"  ML-DSA-65 private key: {len(priv_key)} bytes")
        print(f"  ML-DSA-65 signature: {len(signature)} bytes")
        print(f"  ML-KEM-768 public key: {len(kem_pub)} bytes")
        print(f"  ML-KEM-768 private key: {len(kem_priv)} bytes")

        # Verify expected sizes
        assert len(pub_key) == 1952
        assert len(signature) == 3309
        assert len(kem_pub) == 1184


class TestStressTests:
    """Stress tests for wallet operations."""

    @pytest.mark.skipif(not backend_available(), reason="liboqs not available")
    def test_many_keypairs_generation(self):
        """Test generating many keypairs."""
        wallet = HybridWallet()

        # Generate 50 keypairs
        start = time.time()
        for _ in range(50):
            wallet.generate_hybrid_keypair()
        elapsed = time.time() - start

        print(f"Generated 50 keypairs in {elapsed:.2f}s")
        assert len(wallet.public_keys) == 50
        assert elapsed < 60  # Should complete in 60 seconds

    @pytest.mark.skipif(not backend_available(), reason="liboqs not available")
    def test_many_signatures(self):
        """Test creating many signatures."""
        wallet = HybridWallet()
        public_key = wallet.generate_hybrid_keypair()

        # Create 20 signatures
        start = time.time()
        for i in range(20):
            wallet.sign_transaction_hybrid(
                f"transaction {i}".encode(), public_key.key_id
            )
        elapsed = time.time() - start

        print(f"Created 20 signatures in {elapsed:.2f}s")
        assert elapsed < 60  # Should complete in 60 seconds
