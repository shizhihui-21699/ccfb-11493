"""密钥分层:主密钥(KEK)包裹数据密钥(DEK),DEK 存库,内存缓存解密后的 DEK。

密钥种类(kind):
  - data  : 字段加密密钥,按字段一把,可轮换(rotation)
  - index : 盲索引 HMAC 密钥,按字段一把,长期不变(轮换它等于重建全部索引)

状态机: active -> retiring -> retired
  - active   : 当前写入使用
  - retiring : 不再写入,但还有存量数据用它加密,可读
  - retired  : 全部数据已迁走,仅保留用于审计/兜底读取
"""
from __future__ import annotations

import sqlite3
import time
import uuid

from . import crypto

DDL_KEYS = """
CREATE TABLE IF NOT EXISTS _keys (
    key_id      TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,          -- 'data' | 'index'
    field       TEXT NOT NULL,
    wrapped_key BLOB NOT NULL,
    status      TEXT NOT NULL,          -- 'active' | 'retiring' | 'retired'
    created_at  REAL NOT NULL
);
"""

DDL_META = """
CREATE TABLE IF NOT EXISTS _meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
"""


class KeyStore:
    def __init__(self, conn: sqlite3.Connection, master_key: bytes):
        self.conn = conn
        self.master_key = master_key
        self._cache: dict[str, bytes] = {}
        self.conn.executescript(DDL_KEYS + DDL_META)
        self.conn.commit()

    # ---- 内部 ----

    def _new_key_id(self, kind: str, field: str) -> str:
        return f"k_{kind}_{field}_{uuid.uuid4().hex[:12]}"

    def _insert_key(self, kind: str, field: str, raw: bytes, status: str) -> str:
        key_id = self._new_key_id(kind, field)
        self.conn.execute(
            "INSERT INTO _keys (key_id, kind, field, wrapped_key, status, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (key_id, kind, field, crypto.wrap_key(self.master_key, raw), status, time.time()),
        )
        self.conn.commit()
        self._cache[key_id] = raw
        return key_id

    # ---- 对外 ----

    def get(self, key_id: str) -> bytes:
        """按 key_id 取解密后的密钥,带内存缓存。"""
        if key_id in self._cache:
            return self._cache[key_id]
        row = self.conn.execute(
            "SELECT wrapped_key FROM _keys WHERE key_id=?", (key_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown key_id: {key_id}")
        raw = crypto.unwrap_key(self.master_key, row[0])
        self._cache[key_id] = raw
        return raw

    def active_key(self, kind: str, field: str) -> tuple[str, bytes]:
        """取该字段当前 active 密钥;没有则创建(惰性初始化)。"""
        row = self.conn.execute(
            "SELECT key_id FROM _keys WHERE kind=? AND field=? AND status='active'",
            (kind, field),
        ).fetchone()
        if row is None:
            key_id = self._insert_key(kind, field, crypto.generate_key(), "active")
            return key_id, self._cache[key_id]
        return row[0], self.get(row[0])

    def set_status(self, key_id: str, status: str) -> None:
        self.conn.execute("UPDATE _keys SET status=? WHERE key_id=?", (status, key_id))
        self.conn.commit()

    def promote_new_data_key(self, field: str) -> tuple[str, str]:
        """为字段生成新 data 密钥并置为 active,旧 active 转为 retiring。

        返回 (old_key_id, new_key_id)。旧密钥不删,存量密文仍可解密。
        """
        old_id, _ = self.active_key("data", field)
        self.conn.execute(
            "UPDATE _keys SET status='retiring' WHERE key_id=?", (old_id,)
        )
        new_id = self._new_key_id("data", field)
        self.conn.execute(
            "INSERT INTO _keys (key_id, kind, field, wrapped_key, status, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (new_id, "data", field,
             crypto.wrap_key(self.master_key, crypto.generate_key()), "active", time.time()),
        )
        self.conn.commit()
        self._cache.pop(new_id, None)
        return old_id, new_id

    # ---- 主密钥轮换:只需重包裹 DEK,不碰业务数据 ----

    def rotate_master_key(self, new_master_key: bytes) -> None:
        rows = self.conn.execute("SELECT key_id, wrapped_key FROM _keys").fetchall()
        rewrapped = [
            (crypto.wrap_key(new_master_key, crypto.unwrap_key(self.master_key, blob)), key_id)
            for key_id, blob in rows
        ]
        with self.conn:
            self.conn.executemany("UPDATE _keys SET wrapped_key=? WHERE key_id=?", rewrapped)
        self.master_key = new_master_key
        self._cache.clear()

    # ---- 主密钥世代标记(配合文件型主密钥存储做崩溃一致性) ----

    def master_generation(self) -> int:
        row = self.conn.execute(
            "SELECT v FROM _meta WHERE k='master_generation'").fetchone()
        return int(row[0]) if row else 0

    def set_master_generation(self, gen: int) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO _meta (k,v) VALUES ('master_generation',?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (str(gen),),
            )
