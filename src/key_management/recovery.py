"""
Key Recovery Module
BIP39 seed phrases and recovery mechanisms
"""

import hashlib
import os
from typing import List, Tuple, Optional


class SeedPhraseManager:
    """
    Manage BIP39-compatible seed phrases for key recovery
    
    Features:
    - Generate 12/24 word seed phrases
    - Derive keys from seed phrases
    - Validate seed phrase checksums
    """
    
    # BIP39 English word list (first 256 words for demo)
    BIP39_WORDLIST = [
        "abandon", "ability", "able", "about", "above", "abroad", "abs", "absence",
        "absolute", "absorb", "abuse", "access", "accident", "account", "accuse",
        "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor",
        "actual", "acuity", "acute", "ad", "adapt", "add", "addict", "added",
        "adder", "addicted", "adding", "addition", "additive", "address", "adds",
        "adduce", "adeem", "adenine", "adept", "adequacy", "adequate", "adhere",
        # ... (full BIP39 wordlist would have 2048 words)
        # For brevity, using truncated list
    ]
    
    def __init__(self):
        """Initialize seed phrase manager"""
        self.word_list = self.BIP39_WORDLIST
    
    def generate_entropy(self, num_words: int = 12) -> bytes:
        """
        Generate random entropy for seed phrase
        
        Args:
            num_words: 12 or 24 word phrase
            
        Returns:
            Random entropy bytes
        """
        if num_words not in (12, 24):
            raise ValueError("num_words must be 12 or 24")
        
        # Entropy is 128 bits for 12 words, 256 bits for 24 words
        entropy_bytes = 16 if num_words == 12 else 32
        return os.urandom(entropy_bytes)
    
    def entropy_to_mnemonic(self, entropy: bytes) -> str:
        """
        Convert entropy to BIP39 mnemonic seed phrase
        
        Args:
            entropy: Random entropy bytes
            
        Returns:
            BIP39 mnemonic phrase
        """
        if len(entropy) not in (16, 32):
            raise ValueError("Entropy must be 16 or 32 bytes")
        
        # Calculate checksum
        checksum = self._calculate_checksum(entropy)
        combined = entropy + checksum
        
        # Convert to bits
        bits = ''.join(f'{byte:08b}' for byte in combined)
        
        # Split into 11-bit chunks
        mnemonic_indices = []
        for i in range(0, len(bits), 11):
            chunk = bits[i:i+11]
            index = int(chunk, 2)
            mnemonic_indices.append(index)
        
        # Convert indices to words
        mnemonic_words = [self.word_list[i] for i in mnemonic_indices]
        return ' '.join(mnemonic_words)
    
    def mnemonic_to_entropy(self, mnemonic: str) -> Tuple[bytes, bool]:
        """
        Convert BIP39 mnemonic back to entropy
        
        Args:
            mnemonic: BIP39 mnemonic phrase
            
        Returns:
            Tuple of (entropy_bytes, is_valid_checksum)
        """
        words = mnemonic.split()
        
        if len(words) not in (12, 24):
            return None, False
        
        # Convert words to indices
        try:
            indices = []
            for word in words:
                if word not in self.word_list:
                    return None, False
                indices.append(self.word_list.index(word))
        except ValueError:
            return None, False
        
        # Convert indices to bits
        bits = ''.join(f'{index:011b}' for index in indices)
        
        # Split entropy and checksum
        if len(words) == 12:
            entropy_bits = bits[:-4]  # Last 4 bits are checksum
            checksum_bits = bits[-4:]
        else:
            entropy_bits = bits[:-8]  # Last 8 bits are checksum
            checksum_bits = bits[-8:]
        
        # Convert to bytes
        entropy = bytes(
            int(entropy_bits[i:i+8], 2)
            for i in range(0, len(entropy_bits), 8)
        )
        
        # Verify checksum
        expected_checksum = self._calculate_checksum(entropy)
        expected_checksum_bits = ''.join(f'{byte:08b}' for byte in expected_checksum)
        
        expected_checksum_bits = (
            expected_checksum_bits[:-4] if len(words) == 12
            else expected_checksum_bits[:-8]
        )
        
        is_valid = checksum_bits == expected_checksum_bits[:len(checksum_bits)]
        
        return entropy, is_valid
    
    def _calculate_checksum(self, entropy: bytes) -> bytes:
        """
        Calculate BIP39 checksum
        
        Args:
            entropy: Entropy bytes
            
        Returns:
            Checksum bytes (1/4 of SHA256 hash)
        """
        hash_bytes = hashlib.sha256(entropy).digest()
        
        if len(entropy) == 16:  # 12 words
            return bytes([hash_bytes[0] >> 4])  # First 4 bits
        else:  # 32 bytes = 24 words
            return bytes([hash_bytes[0]])  # First 8 bits
    
    def derive_seed_bytes(self, mnemonic: str, passphrase: str = "") -> bytes:
        """
        Derive 512-bit seed from mnemonic using PBKDF2
        
        Args:
            mnemonic: BIP39 mnemonic phrase
            passphrase: Optional passphrase for additional security
            
        Returns:
            512-bit seed bytes
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        
        password = ("mnemonic" + passphrase).encode()
        salt = mnemonic.encode()
        
        kdf = PBKDF2(
            algorithm=hashes.SHA512(),
            length=64,
            salt=salt,
            iterations=2048,
        )
        
        return kdf.derive(password)
    
    def generate_wallet_seed(self, num_words: int = 12,
                            passphrase: str = "") -> Tuple[str, bytes]:
        """
        Generate complete wallet seed from mnemonic
        
        Args:
            num_words: 12 or 24 word phrase
            passphrase: Optional passphrase
            
        Returns:
            Tuple of (mnemonic_phrase, seed_bytes)
        """
        entropy = self.generate_entropy(num_words)
        mnemonic = self.entropy_to_mnemonic(entropy)
        seed = self.derive_seed_bytes(mnemonic, passphrase)
        
        return mnemonic, seed
    
    def validate_mnemonic(self, mnemonic: str) -> bool:
        """
        Validate a mnemonic phrase
        
        Args:
            mnemonic: BIP39 mnemonic to validate
            
        Returns:
            True if valid checksum and valid words
        """
        entropy, is_valid = self.mnemonic_to_entropy(mnemonic)
        return is_valid and entropy is not None
    
    def __repr__(self) -> str:
        return f"SeedPhraseManager(wordlist_size={len(self.word_list)})"
