#!/usr/bin/env python3
"""
Contains methods and attributes
for authentication
"""
from bcrypt import hashpw, gensalt


def _hash_password(password: str) -> bytes:
    """
    Encrypts password.
    Args:
        password: The password to be encrypted.
    Returns:
        bytes
    """
    return hashpw(password.encode(), gensalt())
