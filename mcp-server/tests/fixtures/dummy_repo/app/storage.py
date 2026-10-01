"""Storage helpers with planted deserialization and error-handling issues."""

import pickle


def load(blob: bytes):
    """Planted: unsafe pickle deserialization + bare except."""
    try:
        return pickle.loads(blob)
    except:
        return None
