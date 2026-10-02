"""BIP39-compatible mnemonic generation and validation."""

from __future__ import annotations

import hashlib
import secrets
from typing import Optional, Tuple

from mnemonic import Mnemonic


class SeedPhraseManager:
    """Manage standard English BIP39 12- and 24-word mnemonics."""

    def __init__(self, language: str = "english") -> None:
        try:
            self._mnemonic = Mnemonic(language)
        except Exception as exc:
            raise ValueError(f"Unsupported BIP39 language: {language}") from exc
        self.word_list = list(self._mnemonic.wordlist)

    def generate_entropy(self, num_words: int = 12) -> bytes:
        if num_words not in (12, 24):
            raise ValueError("num_words must be 12 or 24")
        return secrets.token_bytes(16 if num_words == 12 else 32)

    def entropy_to_mnemonic(self, entropy: bytes) -> str:
        if not isinstance(entropy, (bytes, bytearray, memoryview)):
            raise TypeError("entropy must be bytes-like")
        entropy = bytes(entropy)
        if len(entropy) not in (16, 32):
            raise ValueError("Entropy must be 16 or 32 bytes")
        return self._mnemonic.to_mnemonic(entropy)

    def mnemonic_to_entropy(self, mnemonic: str) -> Tuple[Optional[bytes], bool]:
        if not isinstance(mnemonic, str):
            return None, False
        words = mnemonic.split()
        if len(words) not in (12, 24):
            return None, False
        try:
            entropy = bytes.fromhex(self._mnemonic.to_entropy(mnemonic).hex())
        except (ValueError, TypeError):
            return None, False
        return entropy, self._mnemonic.check(mnemonic)

    def _calculate_checksum(self, entropy: bytes) -> bytes:
        if len(entropy) not in (16, 32):
            raise ValueError("Entropy must be 16 or 32 bytes")
        checksum_bytes = hashlib.sha256(entropy).digest()
        return checksum_bytes[:1]

    def derive_seed_bytes(self, mnemonic: str, passphrase: str = "") -> bytes:
        if not self.validate_mnemonic(mnemonic):
            raise ValueError("Invalid BIP39 mnemonic")
        if not isinstance(passphrase, str):
            raise TypeError("passphrase must be a string")
        return self._mnemonic.to_seed(mnemonic, passphrase)

    def generate_wallet_seed(
        self,
        num_words: int = 12,
        passphrase: str = "",
    ) -> Tuple[str, bytes]:
        mnemonic = self.entropy_to_mnemonic(self.generate_entropy(num_words))
        return mnemonic, self.derive_seed_bytes(mnemonic, passphrase)

    def validate_mnemonic(self, mnemonic: str) -> bool:
        try:
            return isinstance(mnemonic, str) and self._mnemonic.check(mnemonic)
        except (TypeError, ValueError):
            return False

    def __repr__(self) -> str:
        return f"SeedPhraseManager(wordlist_size={len(self.word_list)})"