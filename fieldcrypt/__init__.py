"""fieldcrypt:SQLite 字段级加密数据访问库。

- AES-256-GCM 字段加密,信封格式自带 key_id
- HMAC-SHA256 盲索引(截断 8 字节)支持等值查询
- 主密钥包裹数据密钥的两层密钥结构
- 主密钥轮换 = 重包裹(秒级);数据密钥轮换 = 后台分批重加密,断点续跑
"""

from .db import EncryptedDB, FIELD_SPECS, normalize_idcard, normalize_phone

__all__ = ["EncryptedDB", "FIELD_SPECS", "normalize_phone", "normalize_idcard"]
