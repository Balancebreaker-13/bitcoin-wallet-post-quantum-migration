"""
Key Management Module
Secure storage, encryption, and recovery mechanisms
"""

from .key_store import SecureKeyStore
from .recovery import SeedPhraseManager

__all__ = [
    'SecureKeyStore',
    'SeedPhraseManager',
]

__version__ = '0.1.0'
