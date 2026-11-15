"""基准测试:明文 vs 字段级加密的写入/查询开销。

对比三组:
  plain     明文表,普通索引等值查询
  encrypted 字段加密 + 盲索引等值查询(含解密)
  scan      加密表不用盲索引、全表解密扫描(对照,说明盲索引的意义)
"""
import os
import random
import shutil
import sqlite3
import statistics
import tempfile
import time

from fieldcrypt import EncryptedDB

N_ROWS = 20_000
N_QUERIES = 2_000


def bench(label, fn):
    t0 = time.perf_counter()
    r = fn()
    dt = time.perf_counter() - t0
    print(f"  {label:<28} {dt:8.3f}s")
    return dt, r


def main():
    d = tempfile.mkdtemp()
    try:
        enc_path = os.path.join(d, "enc.db")
        plain_path = os.path.join(d, "plain.db")
        mk_path = os.path.join(d, "master.key")

        phones = [f"138{random.randrange(10**8):08d}" for _ in range(N_ROWS)]
        idcards = [f"1101011990{random.randrange(10**8):08d}X" for _ in range(N_ROWS)]

        # ---------- 写入 ----------
        print(f"[insert] {N_ROWS} rows")
        db = EncryptedDB.open(enc_path, mk_path)
        t_enc_insert, _ = bench("encrypted (AES-GCM+HMAC)", lambda:
            db.insert_many("users", [
                {"name": f"u{i}", "phone": phones[i], "idcard": idcards[i]}
                for i in range(N_ROWS)]))

        pc = sqlite3.connect(plain_path)
        pc.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, phone TEXT, idcard TEXT)")
        pc.execute("CREATE INDEX idx_phone ON users(phone)")
        t_plain_insert, _ = bench("plain", lambda: (
            pc.executemany("INSERT INTO users (name,phone,idcard) VALUES (?,?,?)",
                           [(f"u{i}", phones[i], idcards[i]) for i in range(N_ROWS)]),
            pc.commit()))

        # ---------- 等值查询 ----------
        print(f"[point query] {N_QUERIES} lookups by phone")
        sample = random.sample(phones, N_QUERIES)

        def enc_queries():
            lat = []
            for p in sample:
                t0 = time.perf_counter()
                db.find_one_by("users", "phone", p)
                lat.append(time.perf_counter() - t0)
            return lat

        def plain_queries():
            lat = []
            for p in sample:
                t0 = time.perf_counter()
                pc.execute("SELECT * FROM users WHERE phone=?", (p,)).fetchone()
                lat.append(time.perf_counter() - t0)
            return lat

        t_enc_q, enc_lat = bench("encrypted (blind index+decrypt)", enc_queries)
        t_plain_q, plain_lat = bench("plain (btree index)", plain_queries)

        # 对照:不用盲索引的全表解密扫描(查 50 次就够说明问题了)
        def scan_queries():
            lat = []
            for p in sample[:50]:
                t0 = time.perf_counter()
                [r for r in db.all_rows("users") if r["phone"] == p]
                lat.append(time.perf_counter() - t0)
            return lat
        t_scan, scan_lat = bench("encrypted full-scan x50 (no idx)", scan_queries)

        # ---------- 汇总 ----------
        print("\n[summary]")
        print(f"  insert:  plain {N_ROWS/t_plain_insert:>10,.0f} rows/s | "
              f"encrypted {N_ROWS/t_enc_insert:>10,.0f} rows/s "
              f"({t_enc_insert/t_plain_insert:.1f}x slower)")
        pq, eq = statistics.median(plain_lat), statistics.median(enc_lat)
        print(f"  query:   plain median {pq*1e6:>8.1f}us | encrypted median {eq*1e6:>8.1f}us "
              f"({eq/pq:.1f}x slower)")
        sq = statistics.median(scan_lat)
        print(f"  query:   encrypted w/o blind index median {sq*1e3:>8.1f}ms "
              f"({sq/eq:,.0f}x slower than blind index)")

        # ---------- 轮换耗时参考 ----------
        print("\n[rotation] re-encrypt phone column")
        job = db.start_data_rotation("users", "phone")
        t0 = time.perf_counter()
        db.resume_rotations(batch_size=1000)
        dt = time.perf_counter() - t0
        print(f"  {N_ROWS} rows re-encrypted in {dt:.2f}s ({N_ROWS/dt:,.0f} rows/s)")

        db.close()
        pc.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
