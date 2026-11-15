"""EncryptedDB:字段级加密的数据访问层。

用法:
    db = EncryptedDB.open("app.db", master_key_path="master.key")
    db.insert("users", {"name": "张三", "phone": "138-0000-1234", "idcard": "110...X"})
    row = db.find_one_by("users", "phone", "13800001234")   # 盲索引等值查询
    db.rotate_master_key()          # 主密钥轮换:只重包裹 DEK,秒级
    db.start_data_rotation("users", "phone")   # 数据密钥轮换:登记后台任务
    db.resume_rotations()           # 跑到完;进程被杀后重启再调一次即可续跑
"""
from __future__ import annotations

import re
import sqlite3
from typing import Callable

from . import crypto
from .keystore import KeyStore
from .masterkey import MasterKeyFile
from .rotation import RotationManager


def normalize_phone(s: str) -> str:
    return re.sub(r"\D", "", s)


def normalize_idcard(s: str) -> str:
    return s.strip().upper()


# 表 -> {字段: 归一化函数}。归一化同时用于盲索引和写入前清洗,
# 保证 "138-0000-1234" 和 "13800001234" 命中同一索引。
FIELD_SPECS: dict[str, dict[str, Callable[[str], str]]] = {
    "users": {
        "phone": normalize_phone,
        "idcard": normalize_idcard,
    },
}

DDL_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT,
    phone_enc  TEXT,
    phone_idx  BLOB,
    idcard_enc TEXT,
    idcard_idx BLOB
);
CREATE INDEX IF NOT EXISTS idx_users_phone_idx  ON users(phone_idx);
CREATE INDEX IF NOT EXISTS idx_users_idcard_idx ON users(idcard_idx);
"""


class EncryptedDB:
    def __init__(self, conn: sqlite3.Connection, keystore: KeyStore,
                 master_file: MasterKeyFile | None = None):
        self.conn = conn
        self.keystore = keystore
        self.master_file = master_file
        self.rotations = RotationManager(conn, keystore, self._aad)

    # ---- 构造 ----

    @classmethod
    def open(cls, db_path: str, master_key_path: str = "master.key") -> "EncryptedDB":
        mf = MasterKeyFile(master_key_path)
        master_key, gen = mf.load_or_create()
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        ks = KeyStore(conn, master_key)
        db_gen = ks.master_generation()
        if db_gen == 0:
            ks.set_master_generation(gen)
        elif db_gen != gen:
            # 上次主密钥轮换在"写文件"和"重包裹"之间崩溃,按库里的世代取钥
            master_key = mf.key_for_generation(db_gen)
            ks = KeyStore(conn, master_key)
        db = cls(conn, ks, mf)
        db.conn.executescript(DDL_USERS)
        db.conn.commit()
        return db

    def close(self) -> None:
        self.conn.close()

    # ---- 加解密辅助 ----

    @staticmethod
    def _aad(table: str, field: str) -> bytes:
        return f"fieldcrypt:v1:{table}:{field}".encode("utf-8")

    def _encrypt_value(self, table: str, field: str, value: str) -> tuple[str, bytes]:
        normalize = FIELD_SPECS[table][field]
        normalized = normalize(value)
        key_id, dek = self.keystore.active_key("data", field)
        _, idx_key = self.keystore.active_key("index", field)
        env = crypto.encrypt_field(dek, key_id, normalized, self._aad(table, field))
        idx = crypto.blind_index(idx_key, field, normalized)
        return env, idx

    def _decrypt_value(self, table: str, field: str, envelope: str) -> str:
        key_id = crypto.envelope_key_id(envelope)
        dek = self.keystore.get(key_id)  # 任意世代的密钥都能解,轮换期间新旧可读
        return crypto.decrypt_field(dek, envelope, self._aad(table, field))

    # ---- 业务接口 ----

    def insert(self, table: str, row: dict) -> int:
        ids = self.insert_many(table, [row])
        return ids[0]

    def insert_many(self, table: str, rows: list[dict]) -> list[int]:
        """批量插入,单事务提交。加密是 CPU 活,批量时吞吐接近明文批量写。"""
        spec = FIELD_SPECS[table]
        ids = []
        with self.conn:
            for row in rows:
                cols, vals = [], []
                for k, v in row.items():
                    if k in spec:
                        env, idx = self._encrypt_value(table, k, str(v))
                        cols += [f"{k}_enc", f"{k}_idx"]
                        vals += [env, idx]
                    else:
                        cols.append(k)
                        vals.append(v)
                sql = (f"INSERT INTO {table} ({','.join(cols)})"
                       f" VALUES ({','.join('?' * len(cols))})")
                ids.append(self.conn.execute(sql, vals).lastrowid)
        return ids

    def find_by(self, table: str, field: str, value: str) -> list[dict]:
        """盲索引等值查询。截断索引理论上可能误命中,解密后比对兜底。"""
        spec = FIELD_SPECS[table]
        normalized = spec[field](value)
        _, idx_key = self.keystore.active_key("index", field)
        idx = crypto.blind_index(idx_key, field, normalized)
        cur = self.conn.execute(
            f"SELECT * FROM {table} WHERE {field}_idx = ?", (idx,)
        )
        cols = [d[0] for d in cur.description]
        out = []
        for r in cur.fetchall():
            row = self._decrypt_row(table, dict(zip(cols, r)))
            if row[field] == normalized:  # 误命中过滤
                out.append(row)
        return out

    def find_one_by(self, table: str, field: str, value: str) -> dict | None:
        rows = self.find_by(table, field, value)
        return rows[0] if rows else None

    def get(self, table: str, row_id: int) -> dict | None:
        cur = self.conn.execute(f"SELECT * FROM {table} WHERE id=?", (row_id,))
        row = cur.fetchone()
        if row is None:
            return None
        cols = [d[0] for d in cur.description]
        return self._decrypt_row(table, dict(zip(cols, row)))

    def all_rows(self, table: str) -> list[dict]:
        cur = self.conn.execute(f"SELECT * FROM {table} ORDER BY id")
        cols = [d[0] for d in cur.description]
        return [self._decrypt_row(table, dict(zip(cols, r))) for r in cur.fetchall()]

    def _decrypt_row(self, table: str, raw: dict) -> dict:
        out = {}
        spec = FIELD_SPECS[table]
        for k, v in raw.items():
            if k.endswith("_enc"):
                field = k[:-4]
                out[field] = self._decrypt_value(table, field, v) if v is not None else None
            elif k.endswith("_idx") and k[:-4] in spec:
                continue  # 索引列不外泄
            else:
                out[k] = v
        return out

    # ---- 密钥轮换 ----

    def rotate_master_key(self) -> int:
        """主密钥轮换:重新包裹所有 DEK,不碰业务数据,返回新世代号。"""
        if self.master_file is None:
            raise RuntimeError("no master key file configured")
        new_key, new_gen = self.master_file.add_generation()  # 先落新主密钥
        self.keystore.rotate_master_key(new_key)              # 再重包裹(单事务)
        self.keystore.set_master_generation(new_gen)
        return new_gen

    def start_data_rotation(self, table: str, field: str) -> str:
        return self.rotations.start(table, field)

    def resume_rotations(self, batch_size: int = 500) -> dict[str, int]:
        return self.rotations.resume_all(batch_size)

    def rotation_status(self) -> list[dict]:
        return self.rotations.status()
