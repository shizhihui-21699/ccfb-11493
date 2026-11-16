"""Field-level AES-256-GCM encryption and HMAC blind indexes.

Ciphertext layout (BLOB):
    MAGIC(2) | dek_id(4, big-endian) | nonce(12) | ciphertext+GCM tag(16)

The dek_id is embedded so any row can be decrypted as long as its DEK is
still known to the KeyManager -- this is what makes dual-read during key
rotation work without any row-level bookkeeping beyond the key column.

Blind index:
    HMAC-SHA256(derive_index_key(dek, context), normalize(value))[:INDEX_LEN]

The index key is derived from the DEK, never stored, and different per
(table, field) context, so indexes cannot be correlated across columns.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"F1"
NONCE_LEN = 12
DEK_LEN = 32  # AES-256

# Blind-index truncation. 64 bits: for a table of N rows, birthday-collision
# probability is ~N^2 / 2^65 -- at 10M rows that's ~0.005%, and a collision
# only costs an extra row fetched and filtered after decryption (queries
# always verify the decrypted value). 8 bytes keeps the index small and
# B-tree friendly. Raise to 12/16 for very large tables if desired.
INDEX_LEN = 8

_HEADER = struct.Struct(">2sI")  # magic, dek_id


class CipherError(Exception):
    pass


def generate_dek() -> bytes:
    return os.urandom(DEK_LEN)


def encrypt(dek_id: int, dek: bytes, plaintext: str, aad: bytes = b"") -> bytes:
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return _HEADER.pack(MAGIC, dek_id) + nonce + ct


def parse_dek_id(blob: bytes) -> int:
    magic, dek_id = _HEADER.unpack(blob[: _HEADER.size])
    if magic != MAGIC:
        raise CipherError("bad magic: not a fieldcrypto ciphertext")
    return dek_id


def decrypt(dek: bytes, blob: bytes, aad: bytes = b"") -> str:
    magic, _ = _HEADER.unpack(blob[: _HEADER.size])
    if magic != MAGIC:
        raise CipherError("bad magic: not a fieldcrypto ciphertext")
    nonce = blob[_HEADER.size : _HEADER.size + NONCE_LEN]
    ct = blob[_HEADER.size + NONCE_LEN :]
    try:
        pt = AESGCM(dek).decrypt(nonce, ct, aad)
    except Exception as e:  # InvalidTag etc.
        raise CipherError("decryption failed (wrong key or corrupted data)") from e
    return pt.decode("utf-8")


def derive_index_key(dek: bytes, context: str) -> bytes:
    """Per-(dek, context) blind-index key via HMAC-based KDF."""
    return hmac.new(dek, b"fieldcrypto/index/v1:" + context.encode(), hashlib.sha256).digest()


def blind_index(index_key: bytes, normalized_value: str) -> bytes:
    return hmac.new(index_key, normalized_value.encode("utf-8"), hashlib.sha256).digest()[:INDEX_LEN]
