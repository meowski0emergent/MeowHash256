"""
MeowHash256 — C-Binding Wrapper

This module provides Python bindings to the C implementation of MeowHash256
for maximum performance. Falls back to pure Python if the C library is unavailable.

Usage:
    from meowhash256_c import meowhash256, meowhash256_hex

    digest = meowhash256(b"Hello, World!")  # 32 bytes
    hex_str = meowhash256_hex(b"Hello")     # hex string

Requirements:
    Build the C library first: make lib
"""

import os
import ctypes
from pathlib import Path

_lib = None
_use_pure_python = False


def _load_library():
    """Load the C shared library."""
    global _lib, _use_pure_python

    if _lib is not None:
        return _lib

    # Try to find the library
    search_paths = [
        Path(__file__).parent.parent / 'build' / 'libmeowhash256.so',
        Path(__file__).parent.parent / 'build' / 'libmeowhash_v7.so',
        Path('/usr/local/lib/libmeowhash256.so'),
        Path('/usr/lib/libmeowhash256.so'),
    ]

    for lib_path in search_paths:
        if lib_path.exists():
            try:
                _lib = ctypes.CDLL(str(lib_path))
                _lib.meow_hash_v7.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
                _lib.meow_hash_v7.restype = None
                _lib.meow_hash_v7_hex.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
                _lib.meow_hash_v7_hex.restype = None
                return _lib
            except OSError:
                continue

    _use_pure_python = True
    return None


def meowhash256(data: bytes) -> bytes:
    """
    Compute MeowHash256 of the given input data.

    Uses the C implementation for maximum performance.
    Falls back to pure Python if C library is unavailable.

    Args:
        data: Input bytes to hash

    Returns:
        32 bytes (256-bit hash)
    """
    lib = _load_library()

    if _use_pure_python:
        from .meowhash256 import meowhash256 as py_meowhash256
        return py_meowhash256(data)

    output = ctypes.create_string_buffer(32)
    if len(data) == 0:
        lib.meow_hash_v7(None, 0, output)
    else:
        lib.meow_hash_v7(data, len(data), output)
    return output.raw


def meowhash256_hex(data: bytes) -> str:
    """
    Compute MeowHash256 and return as hexadecimal string.

    Uses the C implementation for maximum performance.
    Falls back to pure Python if C library is unavailable.

    Args:
        data: Input bytes to hash

    Returns:
        64-character hexadecimal string
    """
    lib = _load_library()

    if _use_pure_python:
        from .meowhash256 import meowhash256_hex as py_meowhash256_hex
        return py_meowhash256_hex(data)

    hex_buf = ctypes.create_string_buffer(65)
    if len(data) == 0:
        lib.meow_hash_v7_hex(None, 0, hex_buf)
    else:
        lib.meow_hash_v7_hex(data, len(data), hex_buf)
    return hex_buf.value.decode('ascii')


def is_using_c_library() -> bool:
    """Check if the C library is being used."""
    _load_library()
    return not _use_pure_python


# Backward compatibility aliases
meow_hash_v7 = meowhash256
meow_hash_v7_hex = meowhash256_hex


if __name__ == '__main__':
    import sys

    print(f"Using C library: {is_using_c_library()}")

    if len(sys.argv) > 1:
        data = sys.argv[1].encode('utf-8')
    else:
        data = b''

    print(f"Input: {repr(data)}")
    print(f"Hash:  {meowhash256_hex(data)}")
