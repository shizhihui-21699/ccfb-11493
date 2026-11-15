"""加密原语:AES-GCM 字段加密、密钥包裹、HMAC 盲索引。"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENVELOPE_VERSION = "v1"
NONCE_BYTES = 12
KEY_BYTES = 32  # AES-256

# 盲索引截断长度(字节)。取 8 字节(64 bit):
# 生日界下需要 ~2^32 行才有 50% 碰撞,千万级用户表误报率可忽略;
# 且查询侧在解密后会做一次明文比对兜底,截断只影响索引选择性,不影响正确性。
INDEX_TRUNC_BYTES = 8

_KEYWRAP_AAD = b"fieldcrypt:keywrap:v1"


def generate_key() -> bytes:
    return os.urandom(KEY_BYTES)


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("ascii"))


def wrap_key(master_key: bytes, dek: bytes) -> bytes:
    """用主密钥包裹(加密)数据密钥。返回 nonce||ciphertext||tag。"""
    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(master_key).encrypt(nonce, dek, _KEYWRAP_AAD)


def unwrap_key(master_key: bytes, blob: bytes) -> bytes:
    return AESGCM(master_key).decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], _KEYWRAP_AAD)


def encrypt_field(dek: bytes, key_id: str, plaintext: str, aad: bytes = b"") -> str:
    """字段级加密,输出信封格式: v1.<key_id>.<b64(nonce||ct||tag)>。

    key_id 明文放在信封里,解密时据此找密钥 —— 这是多版本密钥共存、
    轮换期间新旧数据都能读的关键。
    """
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return f"{ENVELOPE_VERSION}.{key_id}.{b64e(nonce + ct)}"


def envelope_key_id(envelope: str) -> str:
    return envelope.split(".", 3)[1]


def envelope_prefix(key_id: str) -> str:
    return f"{ENVELOPE_VERSION}.{key_id}."


def decrypt_field(dek: bytes, envelope: str, aad: bytes = b"") -> str:
    version, _key_id, payload = envelope.split(".", 2)
    if version != ENVELOPE_VERSION:
        raise ValueError(f"unsupported envelope version: {version}")
    blob = b64d(payload)
    return AESGCM(dek).decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], aad).decode("utf-8")


def blind_index(index_key: bytes, field: str, normalized_value: str) -> bytes:
    """HMAC-SHA256 盲索引,截断到 INDEX_TRUNC_BYTES。

    索引密钥独立于数据密钥:数据密钥轮换时索引不变,查询无感。
    输入必须先做归一化(如手机号去非数字字符),由调用方保证。
    """
    msg = field.encode("utf-8") + b"\x00" + normalized_value.encode("utf-8")
    return hmac.new(index_key, msg, hashlib.sha256).digest()[:INDEX_TRUNC_BYTES]
