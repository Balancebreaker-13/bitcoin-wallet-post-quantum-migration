"""
Conftest - Pytest configuration and shared fixtures
"""

import pytest
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


@pytest.fixture(scope="session")
def test_config():
    """
    Test configuration fixture
    """
    return {
        'seed_phrase': 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
        'test_password': 'test_password_123',
        'test_amount': 50000000,  # 0.5 BTC in satoshis
    }


@pytest.fixture(scope="function")
def cleanup_wallet_data():
    """
    Cleanup wallet data after each test
    """
    yield
    # Cleanup code would go here
    pass
