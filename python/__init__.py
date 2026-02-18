"""
MeowHash256 — Python Implementation

Two implementations available:
- meowhash256.py     — Pure Python (zero dependencies)
- meowhash256_c.py   — C-binding wrapper (requires built library)

Usage:
    # Pure Python
    from python.meowhash256 import meowhash256, meowhash256_hex

    # C-binding (faster)
    from python.meowhash256_c import meowhash256, meowhash256_hex

    digest = meowhash256(b"Hello")     # 32 bytes
    hex_str = meowhash256_hex(b"Hello")  # hex string
"""

from .meowhash256 import meowhash256, meowhash256_hex

__all__ = ['meowhash256', 'meowhash256_hex']
__version__ = '6.0.0'
