"""
Common Bitcoin hashes.
"""

import hashlib


def sha256(data):
    """{data} must be bytes, returns sha256(data)"""
    assert isinstance(data, bytes)
    return hashlib.sha256(data).digest()


def hash160(data):
    """{data} must be bytes, returns ripemd160(sha256(data))"""
    assert isinstance(data, bytes)
    return hashlib.new("ripemd160", sha256(data)).digest()
