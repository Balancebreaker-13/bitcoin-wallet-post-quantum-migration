#!/usr/bin/env python3
"""
Comprehensive Tests for Post-Quantum Cryptography PoC

Tests cover:
- Dilithium signature scheme
- Kyber key encapsulation mechanism
- Hybrid key generation
- Key import/export functionality
- Error handling
"""

import unittest
import os
import json
import tempfile
from datetime import datetime

# Import PoC modules
from dilithium_demo import DilithiumPoC
from kyber_demo import KyberPoC
from hybrid_key_demo import HybridKeyGenerator, HybridPublicKey, HybridPrivateKey


class TestDilithiumPoC(unittest.TestCase):
    """Test suite for Dilithium PoC implementation"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.dilithium = DilithiumPoC(security_level=3)
    
    def test_initialization(self):
        """Test Dilithium initialization"""
        self.assertEqual(self.dilithium.security_level, 3)
        self.assertEqual(self.dilithium.algorithm_name, "Dilithium3")
        self.assertIsNone(self.dilithium.public_key)
        self.assertIsNone(self.dilithium.private_key)
    
    def test_invalid_security_level(self):
        """Test that invalid security levels raise error"""
        with self.assertRaises(ValueError):
            DilithiumPoC(security_level=4)
    
    def test_keypair_generation(self):
        """Test keypair generation"""
        result = self.dilithium.generate_keypair()
        
        self.assertEqual(result["status"], "success")
        self.assertIn("public_key_size", result)
        self.assertIn("private_key_size", result)
        self.assertGreater(result["public_key_size"], 0)
        self.assertGreater(result["private_key_size"], 0)
        self.assertIsNotNone(self.dilithium.public_key)
        self.assertIsNotNone(self.dilithium.private_key)
    
    def test_message_signing(self):
        """Test message signing"""
        self.dilithium.generate_keypair()
        
        message = "Test message for signing"
        result = self.dilithium.sign_message(message)
        
        self.assertEqual(result["status"], "success")
        self.assertIn("signature_size", result)
        self.assertGreater(result["signature_size"], 0)
        self.assertEqual(result["algorithm"], "Dilithium3")
    
    def test_signing_without_keypair(self):
        """Test that signing without keypair fails"""
        message = "Test message"
        result = self.dilithium.sign_message(message)
        
        self.assertEqual(result["status"], "error")
        self.assertIn("message", result)
    
    def test_all_security_levels(self):
        """Test all supported security levels"""
        for level in [2, 3, 5]:
            dilithium = DilithiumPoC(security_level=level)
            result = dilithium.generate_keypair()
            
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["security_level"], level)
    
    def test_export_keys(self):
        """Test key export functionality"""
        self.dilithium.generate_keypair()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "dilithium_keys.json")
            result = self.dilithium.export_keys(filepath)
            
            self.assertEqual(result["status"], "success")
            self.assertTrue(os.path.exists(filepath))
            
            # Verify exported data
            with open(filepath, 'r') as f:
                keys_data = json.load(f)
            
            self.assertEqual(keys_data["algorithm"], "Dilithium3")
            self.assertIn("public_key", keys_data)
            self.assertIn("private_key", keys_data)
    
    def test_import_keys(self):
        """Test key import functionality"""
        # Generate and export keys
        self.dilithium.generate_keypair()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "dilithium_keys.json")
            self.dilithium.export_keys(filepath)
            
            # Import keys into new instance
            new_dilithium = DilithiumPoC(security_level=3)
            result = new_dilithium.import_keys(filepath)
            
            self.assertEqual(result["status"], "success")
            self.assertEqual(new_dilithium.public_key, self.dilithium.public_key)
            self.assertEqual(new_dilithium.private_key, self.dilithium.private_key)


class TestKyberPoC(unittest.TestCase):
    """Test suite for Kyber KEM PoC implementation"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.kyber = KyberPoC(security_level=768)
    
    def test_initialization(self):
        """Test Kyber initialization"""
        self.assertEqual(self.kyber.security_level, 768)
        self.assertEqual(self.kyber.algorithm_name, "Kyber768")
        self.assertIsNone(self.kyber.public_key)
        self.assertIsNone(self.kyber.secret_key)
    
    def test_invalid_security_level(self):
        """Test that invalid security levels raise error"""
        with self.assertRaises(ValueError):
            KyberPoC(security_level=256)
    
    def test_keypair_generation(self):
        """Test keypair generation"""
        result = self.kyber.generate_keypair()
        
        self.assertEqual(result["status"], "success")
        self.assertIn("public_key_size", result)
        self.assertIn("secret_key_size", result)
        self.assertGreater(result["public_key_size"], 0)
        self.assertGreater(result["secret_key_size"], 0)
    
    def test_encapsulation(self):
        """Test encapsulation process"""
        self.kyber.generate_keypair()
        result = self.kyber.encapsulate()
        
        self.assertEqual(result["status"], "success")
        self.assertIn("ciphertext_size", result)
        self.assertIn("shared_secret_size", result)
        self.assertGreater(result["ciphertext_size"], 0)
        self.assertGreater(result["shared_secret_size"], 0)
    
    def test_decapsulation(self):
        """Test decapsulation process"""
        self.kyber.generate_keypair()
        encap_result = self.kyber.encapsulate()
        
        ciphertext_hex = encap_result.get("_ciphertext")
        decap_result = self.kyber.decapsulate(ciphertext_hex)
        
        self.assertEqual(decap_result["status"], "success")
        self.assertIn("shared_secret_hash", decap_result)
    
    def test_shared_secrets_match(self):
        """Test that encapsulation and decapsulation produce matching secrets"""
        self.kyber.generate_keypair()
        encap_result = self.kyber.encapsulate()
        
        alice_secret = encap_result.get("_shared_secret")
        ciphertext_hex = encap_result.get("_ciphertext")
        
        decap_result = self.kyber.decapsulate(ciphertext_hex)
        bob_secret = decap_result.get("_shared_secret")
        
        self.assertEqual(alice_secret, bob_secret)
    
    def test_all_security_levels(self):
        """Test all supported security levels"""
        for level in [512, 768, 1024]:
            kyber = KyberPoC(security_level=level)
            result = kyber.generate_keypair()
            
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["security_level"], level)
    
    def test_export_keys(self):
        """Test key export functionality"""
        self.kyber.generate_keypair()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "kyber_keys.json")
            result = self.kyber.export_keys(filepath)
            
            self.assertEqual(result["status"], "success")
            self.assertTrue(os.path.exists(filepath))


class TestHybridKeyGenerator(unittest.TestCase):
    """Test suite for Hybrid Key Generator"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.hybrid_gen = HybridKeyGenerator(pqc_security_level=3)
    
    def test_initialization(self):
        """Test hybrid key generator initialization"""
        self.assertEqual(self.hybrid_gen.pqc_security_level, 3)
        self.assertIsNone(self.hybrid_gen.hybrid_pubkey)
        self.assertIsNone(self.hybrid_gen.hybrid_privkey)
    
    def test_hybrid_keypair_generation(self):
        """Test hybrid keypair generation"""
        result = self.hybrid_gen.generate_hybrid_keypair()
        
        self.assertEqual(result["status"], "success")
        self.assertIn("key_id", result)
        self.assertIn("created_at", result)
        self.assertIn("hybrid_public_key", result)
        self.assertIn("summary", result)
        
        # Verify summary has expected fields
        summary = result["summary"]
        self.assertIn("total_pubkey_size", summary)
        self.assertIn("security_level_ecc", summary)
        self.assertIn("security_level_pqc", summary)
    
    def test_get_public_key(self):
        """Test public key retrieval"""
        self.hybrid_gen.generate_hybrid_keypair()
        pubkey = self.hybrid_gen.get_public_key()
        
        self.assertIsNotNone(pubkey)
        self.assertIsInstance(pubkey, HybridPublicKey)
        self.assertIn("secp256k1", pubkey.security_level_ecc)
    
    def test_sign_transaction_hybrid(self):
        """Test hybrid transaction signing"""
        self.hybrid_gen.generate_hybrid_keypair()
        
        tx_data = "Test transaction"
        result = self.hybrid_gen.sign_transaction_hybrid(tx_data)
        
        self.assertEqual(result["status"], "success")
        self.assertIn("transaction_hash", result)
        self.assertIn("combined_signature_size", result)
        self.assertGreater(result["combined_signature_size"], 0)
    
    def test_sign_without_keypair(self):
        """Test that signing without keypair fails"""
        result = self.hybrid_gen.sign_transaction_hybrid("test")
        
        self.assertEqual(result["status"], "error")
    
    def test_export_hybrid_keys(self):
        """Test hybrid key export"""
        self.hybrid_gen.generate_hybrid_keypair()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "hybrid_keys.json")
            result = self.hybrid_gen.export_hybrid_keys(filepath)
            
            self.assertEqual(result["status"], "success")
            self.assertTrue(os.path.exists(filepath))
            
            # Verify exported data
            with open(filepath, 'r') as f:
                keys_data = json.load(f)
            
            self.assertIn("public_key", keys_data)
            self.assertIn("private_key", keys_data)
            self.assertEqual(keys_data["algorithm"], "Hybrid ECC+PQC")
    
    def test_import_hybrid_keys(self):
        """Test hybrid key import"""
        self.hybrid_gen.generate_hybrid_keypair()
        original_key_id = self.hybrid_gen.hybrid_pubkey.key_id
        
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "hybrid_keys.json")
            self.hybrid_gen.export_hybrid_keys(filepath)
            
            # Import into new instance
            new_hybrid_gen = HybridKeyGenerator()
            result = new_hybrid_gen.import_hybrid_keys(filepath)
            
            self.assertEqual(result["status"], "success")
            self.assertEqual(result["key_id"], original_key_id)
    
    def test_different_security_levels(self):
        """Test hybrid generation with different PQC security levels"""
        for level in [2, 3, 5]:
            hybrid_gen = HybridKeyGenerator(pqc_security_level=level)
            result = hybrid_gen.generate_hybrid_keypair()
            
            self.assertEqual(result["status"], "success")
            summary = result["summary"]
            self.assertIn(f"Dilithium{level}", summary["security_level_pqc"])


class TestPoCArtifacts(unittest.TestCase):
    """Test PoC artifacts and output files"""
    
    def test_poc_directory_structure(self):
        """Test that required PoC directories exist"""
        poc_dir = "poc"
        self.assertTrue(os.path.exists(poc_dir), f"Directory {poc_dir} should exist")
    
    def test_poc_files_exist(self):
        """Test that required PoC files exist"""
        required_files = [
            "poc/environment_setup.md",
            "poc/dilithium_demo.py",
            "poc/kyber_demo.py",
            "poc/hybrid_key_demo.py",
            "poc/test_poc.py"
        ]
        
        for filepath in required_files:
            self.assertTrue(os.path.exists(filepath), f"File {filepath} should exist")


class TestIntegration(unittest.TestCase):
    """Integration tests combining multiple components"""
    
    def test_full_hybrid_workflow(self):
        """Test complete hybrid key workflow"""
        # 1. Generate hybrid keypair
        hybrid_gen = HybridKeyGenerator(pqc_security_level=3)
        gen_result = hybrid_gen.generate_hybrid_keypair()
        self.assertEqual(gen_result["status"], "success")
        
        # 2. Get public key
        pubkey = hybrid_gen.get_public_key()
        self.assertIsNotNone(pubkey)
        
        # 3. Sign transaction
        tx_data = "Integration test transaction"
        sign_result = hybrid_gen.sign_transaction_hybrid(tx_data)
        self.assertEqual(sign_result["status"], "success")
        
        # 4. Export keys
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "hybrid_keys.json")
            export_result = hybrid_gen.export_hybrid_keys(filepath)
            self.assertEqual(export_result["status"], "success")
            
            # 5. Import keys
            new_hybrid_gen = HybridKeyGenerator()
            import_result = new_hybrid_gen.import_hybrid_keys(filepath)
            self.assertEqual(import_result["status"], "success")
            
            # 6. Verify imported keys work
            new_pubkey = new_hybrid_gen.get_public_key()
            self.assertEqual(new_pubkey.key_id, pubkey.key_id)
    
    def test_kyber_key_exchange_workflow(self):
        """Test Kyber key exchange workflow"""
        # Alice's side
        alice_kyber = KyberPoC(security_level=768)
        alice_kyber.generate_keypair()
        
        # Alice encapsulates
        encap_result = alice_kyber.encapsulate()
        self.assertEqual(encap_result["status"], "success")
        
        alice_secret = encap_result.get("_shared_secret")
        ciphertext = encap_result.get("_ciphertext")
        
        # Bob receives ciphertext and decapsulates
        bob_kyber = KyberPoC(security_level=768)
        bob_kyber.public_key = alice_kyber.public_key
        bob_kyber.secret_key = alice_kyber.secret_key
        bob_kyber.kem = alice_kyber.kem
        
        decap_result = bob_kyber.decapsulate(ciphertext)
        self.assertEqual(decap_result["status"], "success")
        
        bob_secret = decap_result.get("_shared_secret")
        
        # Verify secrets match
        self.assertEqual(alice_secret, bob_secret)


def run_tests():
    """Run all tests with detailed output"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestDilithiumPoC))
    suite.addTests(loader.loadTestsFromTestCase(TestKyberPoC))
    suite.addTests(loader.loadTestsFromTestCase(TestHybridKeyGenerator))
    suite.addTests(loader.loadTestsFromTestCase(TestPoCArtifacts))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == "__main__":
    result = run_tests()
    
    # Print summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 70)
