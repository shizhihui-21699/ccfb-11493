"""Resumable, batched DEK rotation (data re-encryption).

Flow:
  1. start(): create a new active DEK for the (table, field) purpose; mark the
     old one 'retiring'; persist a _rotations row (crash-safe checkpoint).
  2. run_batch(n): re-encrypt up to n rows still on the old DEK, ordered by
     rowid; commit after every batch and checkpoint last_rowid. If the process
     is killed, a fresh EncryptedDB + resume() picks up exactly where it stopped.
  3. When a batch finds no rows left: mark old DEK 'retired', drop the
     _rotations row. Done.

Throughout, reads and equality queries work on both key generations:
  - ciphertexts carry their dek_id, so get()/all() decrypt either generation;
  - find_by() builds blind-index candidates from all active+retiring DEKs;
  - new writes always use the new active DEK, so the scan only moves forward.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from . import cipher
from .db import EncryptedDB


@dataclass
class Rotation:
    db: EncryptedDB
    table: str
    field: str
    old_dek: int
    new_dek: int
    last_rowid: int = 0

    # ---- lifecycle ----

    @classmethod
    def start(cls, db: EncryptedDB, table: str, field: str) -> "Rotation":
        spec = db._spec(table)
        if field not in spec["encrypted"]:
            raise KeyError(f"{field!r} is not an encrypted field of {table!r}")
        pending = cls.pending(db, table, field)
        if pending is not None:
            return pending  # idempotent: a rotation is already running
        purpose = f"{table}.{field}"
        old_dek, _ = db.km.active_dek(purpose)
        db.km.set_status(old_dek, "retiring")
        new_dek = db.km.create_dek(purpose, status="active")
        db.conn.execute(
            "INSERT INTO _rotations (table_name, field, old_dek, new_dek, last_rowid)"
            " VALUES (?, ?, ?, ?, 0)",
            (table, field, old_dek, new_dek),
        )
        db.conn.commit()
        return cls(db, table, field, old_dek, new_dek, 0)

    @classmethod
    def pending(cls, db: EncryptedDB, table: str, field: str) -> "Rotation | None":
        r = db.conn.execute(
            "SELECT old_dek, new_dek, last_rowid FROM _rotations"
            " WHERE table_name = ? AND field = ?",
            (table, field),
        ).fetchone()
        if r is None:
            return None
        return cls(db, table, field, r[0], r[1], r[2])

    @classmethod
    def pending_all(cls, db: EncryptedDB) -> list["Rotation"]:
        rows = db.conn.execute(
            "SELECT table_name, field, old_dek, new_dek, last_rowid FROM _rotations"
        ).fetchall()
        return [cls(db, t, f, o, n, lr) for t, f, o, n, lr in rows]

    # ---- work ----

    def run_batch(self, batch_size: int = 500) -> int:
        """Re-encrypt up to batch_size rows. Returns rows processed (0 = finished)."""
        f = self.field
        purpose = f"{self.table}.{f}"
        old_key = self.db.km.get_dek(self.old_dek)
        new_key = self.db.km.get_dek(self.new_dek)
        aad = self.db._aad(self.table, f)
        norm = self.db._tables[self.table]["normalizers"][f]
        new_idx_key = cipher.derive_index_key(new_key, purpose)

        rows = self.db.conn.execute(
            f"SELECT id, {f}_enc FROM {self.table}"
            f" WHERE {f}_key = ? AND id > ? ORDER BY id LIMIT ?",
            (self.old_dek, self.last_rowid, batch_size),
        ).fetchall()
        if not rows:
            self._finish()
            return 0
        with self.db.conn:  # one transaction per batch: the crash boundary
            for rowid, blob in rows:
                plaintext = cipher.decrypt(old_key, blob, aad)
                new_blob = cipher.encrypt(self.new_dek, new_key, plaintext, aad)
                new_idx = cipher.blind_index(new_idx_key, norm(plaintext))
                self.db.conn.execute(
                    f"UPDATE {self.table} SET {f}_enc = ?, {f}_idx = ?, {f}_key = ?"
                    f" WHERE id = ?",
                    (new_blob, new_idx, self.new_dek, rowid),
                )
            self.last_rowid = rows[-1][0]
            self.db.conn.execute(
                "UPDATE _rotations SET last_rowid = ? WHERE table_name = ? AND field = ?",
                (self.last_rowid, self.table, self.field),
            )
        return len(rows)

    def run_to_completion(self, batch_size: int = 500) -> int:
        total = 0
        while True:
            n = self.run_batch(batch_size)
            if n == 0:
                return total
            total += n

    def done(self) -> bool:
        return Rotation.pending(self.db, self.table, self.field) is None

    def remaining(self) -> int:
        return self.db.conn.execute(
            f"SELECT COUNT(*) FROM {self.table} WHERE {self.field}_key = ?",
            (self.old_dek,),
        ).fetchone()[0]

    def _finish(self):
        self.db.km.set_status(self.old_dek, "retired")
        self.db.conn.execute(
            "DELETE FROM _rotations WHERE table_name = ? AND field = ?",
            (self.table, self.field),
        )
        self.db.conn.commit()
