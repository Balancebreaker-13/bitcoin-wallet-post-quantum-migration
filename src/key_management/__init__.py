"""
Key Management Module
Secure storage, encryption, and recovery mechanisms
"""

from .key_store import KeyStoreError, SecureKeyStore
from .recovery import SeedPhraseManager

__all__ = [
    'SecureKeyStore',
    'KeyStoreError',
    'SeedPhraseManager',
]

__version__ = '0.1.0'
