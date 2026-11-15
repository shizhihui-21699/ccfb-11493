"""数据密钥轮换:后台分批重加密,断点续跑。

核心机制:
  - 每个加密字段值自带 key_id(信封格式),新旧密钥的数据天然共存可读
  - 盲索引用独立的 index 密钥,轮换 data 密钥时索引不变,查询全程无感
  - 进度落库(_rotation_state),每批提交一次;进程被杀后重启,从 last_rowid 继续
  - 轮换期间写入走新密钥(active 已切换),重加密只碰旧 key_id 的行,互不干扰
"""
from __future__ import annotations

import sqlite3
import time

from . import crypto

DDL_ROTATION = """
CREATE TABLE IF NOT EXISTS _rotation_state (
    job_id      TEXT PRIMARY KEY,       -- '<table>.<field>'
    table_name  TEXT NOT NULL,
    field       TEXT NOT NULL,
    old_key_id  TEXT NOT NULL,
    new_key_id  TEXT NOT NULL,
    last_rowid  INTEGER NOT NULL DEFAULT 0,
    done_rows   INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL,          -- 'running' | 'done'
    updated_at  REAL NOT NULL
);
"""


class RotationManager:
    def __init__(self, conn: sqlite3.Connection, keystore, aad_for):
        self.conn = conn
        self.keystore = keystore
        self.aad_for = aad_for  # (table, field) -> bytes
        self.conn.executescript(DDL_ROTATION)
        self.conn.commit()

    def start(self, table: str, field: str) -> str:
        """切换 active 数据密钥并登记重加密任务,返回 job_id。"""
        job_id = f"{table}.{field}"
        row = self.conn.execute(
            "SELECT status FROM _rotation_state WHERE job_id=?", (job_id,)
        ).fetchone()
        if row and row[0] == "running":
            return job_id  # 幂等:已有在跑的任务
        old_id, new_id = self.keystore.promote_new_data_key(field)
        with self.conn:
            self.conn.execute(
                "INSERT INTO _rotation_state"
                " (job_id, table_name, field, old_key_id, new_key_id,"
                "  last_rowid, done_rows, status, updated_at)"
                " VALUES (?,?,?,?,?,0,0,'running',?)",
                (job_id, table, field, old_id, new_id, time.time()),
            )
        return job_id

    def pending_jobs(self) -> list[dict]:
        cur = self.conn.execute(
            "SELECT job_id, table_name, field, old_key_id, new_key_id,"
            "       last_rowid, done_rows, status FROM _rotation_state"
            " WHERE status='running'"
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def status(self) -> list[dict]:
        cur = self.conn.execute(
            "SELECT job_id, table_name, field, old_key_id, new_key_id,"
            "       last_rowid, done_rows, status FROM _rotation_state"
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def run_batch(self, job_id: str, batch_size: int = 500) -> int:
        """处理一批,返回本批重加密的行数;返回 0 表示该任务完成。

        每批一个事务:行更新 + 检查点推进一起提交,崩溃后最多重做一批。
        """
        job = self.conn.execute(
            "SELECT table_name, field, old_key_id, new_key_id, last_rowid"
            " FROM _rotation_state WHERE job_id=? AND status='running'",
            (job_id,),
        ).fetchone()
        if job is None:
            return 0
        table, field, old_id, new_id, last_rowid = job
        enc_col = f"{field}_enc"
        prefix = crypto.envelope_prefix(old_id)

        rows = self.conn.execute(
            f"SELECT rowid, {enc_col} FROM {table}"
            f" WHERE rowid > ? AND substr({enc_col}, 1, ?) = ?"
            f" ORDER BY rowid LIMIT ?",
            (last_rowid, len(prefix), prefix, batch_size),
        ).fetchall()

        if not rows:
            with self.conn:
                self.conn.execute(
                    "UPDATE _rotation_state SET status='done', updated_at=? WHERE job_id=?",
                    (time.time(), job_id),
                )
            self.keystore.set_status(old_id, "retired")
            return 0

        old_dek = self.keystore.get(old_id)
        new_dek = self.keystore.get(new_id)
        aad = self.aad_for(table, field)
        done = 0
        max_rowid = last_rowid
        with self.conn:  # 单事务:重加密 + 检查点原子提交
            for rowid, envelope in rows:
                max_rowid = rowid
                plaintext = crypto.decrypt_field(old_dek, envelope, aad)
                new_env = crypto.encrypt_field(new_dek, new_id, plaintext, aad)
                # 乐观并发:行若被并发写入改过(信封变了)就跳过,
                # 新写入本来就用新密钥,不会漏。
                cur = self.conn.execute(
                    f"UPDATE {table} SET {enc_col}=? WHERE rowid=? AND {enc_col}=?",
                    (new_env, rowid, envelope),
                )
                done += cur.rowcount
            self.conn.execute(
                "UPDATE _rotation_state SET last_rowid=?, done_rows=done_rows+?,"
                " updated_at=? WHERE job_id=?",
                (max_rowid, done, time.time(), job_id),
            )
        return done

    def run_until_done(self, job_id: str, batch_size: int = 500) -> int:
        total = 0
        while True:
            n = self.run_batch(job_id, batch_size)
            total += n
            if n == 0:
                return total

    def resume_all(self, batch_size: int = 500) -> dict[str, int]:
        """重启后调用:把所有 running 状态的任务跑到完。"""
        return {
            job["job_id"]: self.run_until_done(job["job_id"], batch_size)
            for job in self.pending_jobs()
        }
