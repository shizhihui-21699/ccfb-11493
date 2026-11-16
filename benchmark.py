"""Benchmark: plaintext SQLite vs fieldcrypto-encrypted access.

Measures, on the same machine and same row count:
  1. bulk insert throughput
  2. indexed equality lookup by phone (plaintext index vs blind index)
  3. DEK rotation (background re-encryption) throughput

Run:  .venv/bin/python benchmark.py [n_rows]
"""

import random
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

from fieldcrypto import EncryptedDB, FileMasterKeyring, Rotation, normalize_id_card, normalize_phone

N = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
QUERIES = 500


def make_rows(n):
    rng = random.Random(42)
    rows = []
    for i in range(n):
        rows.append({
            "name": f"user{i}",
            "id_card": f"11010119{rng.randint(60, 99):02d}{rng.randint(1, 12):02d}{rng.randint(1, 28):02d}{rng.randint(1000, 9999)}",
            "phone": f"13{rng.randint(0, 9)}{rng.randint(10000000, 99999999)}",
        })
    return rows


def bench(label, fn):
    t0 = time.perf_counter()
    result = fn()
    dt = time.perf_counter() - t0
    return dt, result


def main():
    tmp = Path(tempfile.mkdtemp(prefix="fieldcrypto-bench-"))
    rows = make_rows(N)
    print(f"rows={N}, lookups={QUERIES}  (tmp: {tmp})\n")

    # ---------- plaintext baseline ----------
    plain = sqlite3.connect(tmp / "plain.db")
    plain.execute("PRAGMA journal_mode = WAL")
    plain.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                  " name TEXT, id_card TEXT, phone TEXT)")
    plain.execute("CREATE INDEX idx_phone ON users (phone)")

    def plain_insert_perrow():
        for r in rows:
            plain.execute("INSERT INTO users (name, id_card, phone) VALUES (?, ?, ?)",
                          (r["name"], r["id_card"], r["phone"]))
            plain.commit()

    def plain_insert_batch():
        with plain:
            plain.executemany(
                "INSERT INTO users (name, id_card, phone) VALUES (?, ?, ?)",
                [(r["name"], r["id_card"], r["phone"]) for r in rows],
            )

    t_plain_ins, _ = bench("plain insert per-row", plain_insert_perrow)
    plain.execute("DELETE FROM users")
    t_plain_ins_b, _ = bench("plain insert batch", plain_insert_batch)

    phones = [r["phone"] for r in random.Random(1).sample(rows, QUERIES)]

    def plain_query():
        for p in phones:
            plain.execute("SELECT * FROM users WHERE phone = ?", (p,)).fetchall()

    t_plain_q, _ = bench("plain query", plain_query)

    # ---------- encrypted ----------
    enc = EncryptedDB(tmp / "enc.db", FileMasterKeyring(tmp / "master.key"))
    enc.register_table(
        "users",
        plaintext_fields=["name"],
        encrypted_fields=["id_card", "phone"],
        normalizers={"phone": normalize_phone, "id_card": normalize_id_card},
    )

    t_enc_ins, _ = bench("enc insert per-row", lambda: [enc.insert("users", r) for r in rows])
    enc.conn.execute("DELETE FROM users")
    t_enc_ins_b, _ = bench("enc insert batch", lambda: enc.insert_many("users", rows))

    def enc_query():
        hits = 0
        for p in phones:
            hits += len(enc.find_by("users", "phone", p))
        return hits

    t_enc_q, hits = bench("enc query", enc_query)
    assert hits == QUERIES, f"correctness: expected {QUERIES} hits, got {hits}"

    # ---------- rotation throughput ----------
    rot = Rotation.start(enc, "users", "phone")
    t_rot, total = bench("rotate", lambda: rot.run_to_completion(batch_size=500))
    assert total == N
    # queries still correct after rotation
    assert len(enc.find_by("users", "phone", phones[0])) == 1

    # ---------- report ----------
    def per_op(t, n):
        return f"{t / n * 1e6:8.1f} µs/op"

    print(f"{'operation':<34}{'plaintext':>14}{'encrypted':>14}{'slowdown':>10}")
    print("-" * 72)
    print(f"{'insert (per-row commit)':<34}{per_op(t_plain_ins, N):>14}{per_op(t_enc_ins, N):>14}"
          f"{t_enc_ins / t_plain_ins:>9.1f}x")
    print(f"{'insert (single transaction)':<34}{per_op(t_plain_ins_b, N):>14}{per_op(t_enc_ins_b, N):>14}"
          f"{t_enc_ins_b / t_plain_ins_b:>9.1f}x")
    print(f"{'equality lookup by phone':<34}{per_op(t_plain_q, QUERIES):>14}"
          f"{per_op(t_enc_q, QUERIES):>14}{t_enc_q / t_plain_q:>9.1f}x")
    print()
    print(f"insert totals (per-row):  plain {t_plain_ins:.3f}s   encrypted {t_enc_ins:.3f}s")
    print(f"insert totals (batch):    plain {t_plain_ins_b:.3f}s   encrypted {t_enc_ins_b:.3f}s")
    print(f"query totals:             plain {t_plain_q:.3f}s   encrypted {t_enc_q:.3f}s")
    print(f"DEK rotation:         {total} rows in {t_rot:.3f}s"
          f"  ({total / t_rot:.0f} rows/s, {t_rot / total * 1e6:.0f} µs/row)")
    enc.close()
    plain.close()


if __name__ == "__main__":
    main()
