"""Key hierarchy: master key (KEK) wraps per-purpose data encryption keys (DEK).

DEKs are stored wrapped in the `_deks` table inside the same SQLite database:

    dek_id, purpose, wrapped_dek (nonce||ct), wrap_version, status, created_at

status lifecycle:  active -> retiring -> retired
  - active:   used for new writes
  - retiring: a rotation is in progress; still used for reads and blind-index
              query candidates, but not for new writes
  - retired:  all data re-encrypted; kept only so historical rows (if any)
              remain decryptable; excluded from query candidates

Master-key rotation only re-wraps DEKs (cheap, atomic-ish). Data re-encryption
is DEK rotation and lives in rotation.py.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import cipher

_WRAP_AAD = b"fieldcrypto/dek-wrap/v1"
_WRAP_NONCE_LEN = 12


class MasterKeyError(Exception):
    pass


class FileMasterKeyring:
    """Versioned master keys in a JSON file: {"current": 2, "keys": {"1": b64, "2": b64}}.

    Fine for development. In production, back this with a KMS/HSM: only
    unwrap DEKs in memory, never persist the master key next to the data.
    """

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        if self.path.exists():
            data = json.loads(self.path.read_text())
            self._current = data["current"]
            self._keys = {int(v): base64.b64decode(k) for v, k in data["keys"].items()}
        else:
            self._current = 1
            self._keys = {1: os.urandom(32)}
            self._save()
        os.chmod(self.path, 0o600)

    def _save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({
            "current": self._current,
            "keys": {str(v): base64.b64encode(k).decode() for v, k in self._keys.items()},
        }))
        os.replace(tmp, self.path)

    def current(self) -> tuple[int, bytes]:
        return self._current, self._keys[self._current]

    def get(self, version: int) -> bytes:
        try:
            return self._keys[version]
        except KeyError:
            raise MasterKeyError(f"unknown master key version {version}") from None

    def rotate(self) -> int:
        """Generate a new master key version and make it current."""
        self._current += 1
        self._keys[self._current] = os.urandom(32)
        self._save()
        return self._current


class KeyManager:
    def __init__(self, conn: sqlite3.Connection, master: FileMasterKeyring):
        self.conn = conn
        self.master = master
        self._cache: dict[int, bytes] = {}
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS _deks (
                dek_id       INTEGER PRIMARY KEY AUTOINCREMENT,
                purpose      TEXT NOT NULL,
                wrapped_dek  BLOB NOT NULL,
                wrap_version INTEGER NOT NULL,
                status       TEXT NOT NULL DEFAULT 'active',
                created_at   REAL NOT NULL
            )
        """)
        self.conn.commit()

    # ---- wrap / unwrap ----

    def _wrap(self, dek: bytes, version: int, key: bytes) -> bytes:
        nonce = os.urandom(_WRAP_NONCE_LEN)
        return nonce + AESGCM(key).encrypt(nonce, dek, _WRAP_AAD)

    def _unwrap(self, blob: bytes, version: int) -> bytes:
        key = self.master.get(version)
        nonce, ct = blob[:_WRAP_NONCE_LEN], blob[_WRAP_NONCE_LEN:]
        try:
            return AESGCM(key).decrypt(nonce, ct, _WRAP_AAD)
        except InvalidTag:
            raise MasterKeyError(
                f"cannot unwrap DEK (master key version {version} does not match)"
            ) from None

    # ---- DEK lifecycle ----

    def create_dek(self, purpose: str, status: str = "active") -> int:
        dek = cipher.generate_dek()
        version, key = self.master.current()
        cur = self.conn.execute(
            "INSERT INTO _deks (purpose, wrapped_dek, wrap_version, status, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (purpose, self._wrap(dek, version, key), version, status, time.time()),
        )
        self.conn.commit()
        dek_id = cur.lastrowid
        self._cache[dek_id] = dek
        return dek_id

    def get_dek(self, dek_id: int) -> bytes:
        if dek_id in self._cache:
            return self._cache[dek_id]
        row = self.conn.execute(
            "SELECT wrapped_dek, wrap_version FROM _deks WHERE dek_id = ?", (dek_id,)
        ).fetchone()
        if row is None:
            raise MasterKeyError(f"unknown dek_id {dek_id}")
        dek = self._unwrap(row[0], row[1])
        self._cache[dek_id] = dek
        return dek

    def active_dek(self, purpose: str) -> tuple[int, bytes]:
        row = self.conn.execute(
            "SELECT dek_id FROM _deks WHERE purpose = ? AND status = 'active'"
            " ORDER BY dek_id DESC LIMIT 1",
            (purpose,),
        ).fetchone()
        if row is None:
            dek_id = self.create_dek(purpose)
            return dek_id, self.get_dek(dek_id)
        return row[0], self.get_dek(row[0])

    def candidate_deks(self, purpose: str) -> list[tuple[int, bytes]]:
        """DEKs that may still have live data: active + retiring. Used to build
        the IN-list of blind-index values for equality queries."""
        rows = self.conn.execute(
            "SELECT dek_id FROM _deks WHERE purpose = ? AND status IN ('active','retiring')",
            (purpose,),
        ).fetchall()
        return [(r[0], self.get_dek(r[0])) for r in rows]

    def set_status(self, dek_id: int, status: str):
        self.conn.execute("UPDATE _deks SET status = ? WHERE dek_id = ?", (status, dek_id))
        self.conn.commit()

    # ---- master key rotation: re-wrap only, no data re-encryption ----

    def rotate_master(self) -> int:
        new_version = self.master.rotate()
        _, new_key = self.master.current()
        rows = self.conn.execute("SELECT dek_id, wrapped_dek, wrap_version FROM _deks").fetchall()
        with self.conn:
            for dek_id, wrapped, old_version in rows:
                dek = self._unwrap(wrapped, old_version)
                self.conn.execute(
                    "UPDATE _deks SET wrapped_dek = ?, wrap_version = ? WHERE dek_id = ?",
                    (self._wrap(dek, new_version, new_key), new_version, dek_id),
                )
                self._cache[dek_id] = dek
        return new_version
