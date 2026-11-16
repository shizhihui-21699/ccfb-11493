"""Transparent encrypted data-access layer over SQLite.

For a table registered with encrypted field `phone`, the real schema gets:

    phone_enc  BLOB   -- AES-256-GCM ciphertext (dek_id embedded)
    phone_idx  BLOB   -- truncated HMAC blind index (equality lookups)
    phone_key  INTEGER -- dek_id used (fast rotation scans, debugging)

plus a plain index on phone_idx. Equality queries compute the blind index of
the normalized plaintext under every candidate DEK (active + retiring) and
match `phone_idx IN (?, ...)`, then verify by decrypting -- so results are
correct even with truncated-index collisions, and queries keep working while
a rotation is partially applied.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from . import cipher
from .keys import FileMasterKeyring, KeyManager


def normalize_phone(v: str) -> str:
    """Digits only, so '138-0000-1111', '+86 13800001111' variants collide
    intentionally. Note: strip a leading country code yourself if you mix
    formats with/without it."""
    return re.sub(r"\D", "", v)


def normalize_id_card(v: str) -> str:
    return re.sub(r"\s+", "", v).upper()


def normalize_default(v: str) -> str:
    return v.strip()


class EncryptedDB:
    def __init__(self, path: str | Path, master: FileMasterKeyring):
        self.conn = sqlite3.connect(str(path))
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.km = KeyManager(self.conn, master)
        self._tables: dict[str, dict] = {}
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS _rotations (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                table_name TEXT NOT NULL,
                field      TEXT NOT NULL,
                old_dek    INTEGER NOT NULL,
                new_dek    INTEGER NOT NULL,
                last_rowid INTEGER NOT NULL DEFAULT 0,
                UNIQUE (table_name, field)
            )
        """)
        self.conn.commit()

    # ---- schema ----

    def register_table(
        self,
        name: str,
        plaintext_fields: list[str] | tuple = (),
        encrypted_fields: list[str] | tuple = (),
        normalizers: dict | None = None,
    ):
        normalizers = normalizers or {}
        cols = ["id INTEGER PRIMARY KEY AUTOINCREMENT"]
        for f in plaintext_fields:
            cols.append(f"{f} TEXT")
        for f in encrypted_fields:
            cols += [f"{f}_enc BLOB", f"{f}_idx BLOB", f"{f}_key INTEGER"]
        self.conn.execute(f"CREATE TABLE IF NOT EXISTS {name} ({', '.join(cols)})")
        for f in encrypted_fields:
            self.conn.execute(
                f"CREATE INDEX IF NOT EXISTS idx_{name}_{f}_idx ON {name} ({f}_idx)"
            )
        self.conn.commit()
        self._tables[name] = {
            "plaintext": list(plaintext_fields),
            "encrypted": list(encrypted_fields),
            "normalizers": {f: normalizers.get(f, normalize_default) for f in encrypted_fields},
        }

    def _spec(self, table: str) -> dict:
        if table not in self._tables:
            raise KeyError(f"table {table!r} not registered")
        return self._tables[table]

    @staticmethod
    def _aad(table: str, field: str) -> bytes:
        return f"fieldcrypto/v1:{table}.{field}".encode()

    # ---- writes ----

    def _insert_row(self, table: str, row: dict) -> int:
        spec = self._spec(table)
        cols, vals = [], []
        for f in spec["plaintext"]:
            cols.append(f)
            vals.append(row.get(f))
        for f in spec["encrypted"]:
            v = row.get(f)
            if v is None:
                cols += [f"{f}_enc", f"{f}_idx", f"{f}_key"]
                vals += [None, None, None]
                continue
            dek_id, dek = self.km.active_dek(f"{table}.{f}")
            norm = spec["normalizers"][f](v)
            idx = cipher.blind_index(cipher.derive_index_key(dek, f"{table}.{f}"), norm)
            cols += [f"{f}_enc", f"{f}_idx", f"{f}_key"]
            vals += [cipher.encrypt(dek_id, dek, v, self._aad(table, f)), idx, dek_id]
        cur = self.conn.execute(
            f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
            vals,
        )
        return cur.lastrowid

    def insert(self, table: str, row: dict) -> int:
        rid = self._insert_row(table, row)
        self.conn.commit()
        return rid

    def insert_many(self, table: str, rows: list[dict]) -> list[int]:
        """Bulk insert in a single transaction (one fsync for the whole batch)."""
        with self.conn:
            return [self._insert_row(table, r) for r in rows]

    def update(self, table: str, rowid: int, **fields):
        spec = self._spec(table)
        sets, vals = [], []
        for f, v in fields.items():
            if f in spec["plaintext"]:
                sets.append(f"{f} = ?")
                vals.append(v)
            elif f in spec["encrypted"]:
                if v is None:
                    sets += [f"{f}_enc = NULL", f"{f}_idx = NULL", f"{f}_key = NULL"]
                else:
                    dek_id, dek = self.km.active_dek(f"{table}.{f}")
                    norm = spec["normalizers"][f](v)
                    idx = cipher.blind_index(cipher.derive_index_key(dek, f"{table}.{f}"), norm)
                    sets += [f"{f}_enc = ?", f"{f}_idx = ?", f"{f}_key = ?"]
                    vals += [cipher.encrypt(dek_id, dek, v, self._aad(table, f)), idx, dek_id]
            else:
                raise KeyError(f"unknown field {f!r} for table {table!r}")
        vals.append(rowid)
        self.conn.execute(f"UPDATE {table} SET {', '.join(sets)} WHERE id = ?", vals)
        self.conn.commit()

    # ---- reads ----

    def _decode_row(self, table: str, r: sqlite3.Row | tuple, cols: list[str]) -> dict:
        spec = self._spec(table)
        row = dict(zip(cols, r))
        out = {"id": row["id"]}
        for f in spec["plaintext"]:
            out[f] = row.get(f)
        for f in spec["encrypted"]:
            blob = row.get(f"{f}_enc")
            if blob is None:
                out[f] = None
            else:
                dek = self.km.get_dek(cipher.parse_dek_id(blob))
                out[f] = cipher.decrypt(dek, blob, self._aad(table, f))
        return out

    def _select_cols(self, table: str) -> list[str]:
        spec = self._spec(table)
        cols = ["id"] + spec["plaintext"]
        for f in spec["encrypted"]:
            cols.append(f"{f}_enc")
        return cols

    def get(self, table: str, rowid: int) -> dict | None:
        cols = self._select_cols(table)
        r = self.conn.execute(
            f"SELECT {', '.join(cols)} FROM {table} WHERE id = ?", (rowid,)
        ).fetchone()
        return None if r is None else self._decode_row(table, r, cols)

    def all(self, table: str) -> list[dict]:
        cols = self._select_cols(table)
        rows = self.conn.execute(f"SELECT {', '.join(cols)} FROM {table} ORDER BY id").fetchall()
        return [self._decode_row(table, r, cols) for r in rows]

    def find_by(self, table: str, field: str, value: str) -> list[dict]:
        """Equality lookup on an encrypted field via blind index.

        Computes the index under every candidate DEK (active + retiring) so
        rows written before and during a rotation are both found. Decrypts to
        verify, so truncated-index collisions never leak false positives.
        """
        spec = self._spec(table)
        if field not in spec["encrypted"]:
            raise KeyError(f"{field!r} is not an encrypted field of {table!r}")
        purpose = f"{table}.{field}"
        norm = spec["normalizers"][field](value)
        idx_values = [
            cipher.blind_index(cipher.derive_index_key(dek, purpose), norm)
            for _, dek in self.km.candidate_deks(purpose)
        ]
        cols = self._select_cols(table)
        placeholders = ", ".join("?" * len(idx_values))
        rows = self.conn.execute(
            f"SELECT {', '.join(cols)} FROM {table} WHERE {field}_idx IN ({placeholders})",
            idx_values,
        ).fetchall()
        out = []
        for r in rows:
            decoded = self._decode_row(table, r, cols)
            # verify after decryption: kills false positives from truncation
            if decoded[field] is not None and spec["normalizers"][field](decoded[field]) == norm:
                out.append(decoded)
        return out

    def count(self, table: str) -> int:
        return self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def close(self):
        self.conn.close()
