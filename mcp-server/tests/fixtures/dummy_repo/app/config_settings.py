"""Deliberately vulnerable settings for pipeline tests.

Every value here is FAKE and planted on purpose; nothing is a real
credential. Each line below is expected to trigger one surface check.
"""

import random

password = "dummy-password-1234"     # planted: hardcoded secret
API_KEY = "dummy-api-key-5678"       # planted: hardcoded secret
DEBUG = True                         # planted: debug mode enabled


def session_token() -> str:
    """Planted: non-cryptographic randomness used for a 'secret'."""
    return str(random.randint(0, 999999))
