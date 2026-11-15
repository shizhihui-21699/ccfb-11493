"""功能测试:加解密、盲索引查询、数据密钥轮换、崩溃续跑、主密钥轮换。"""
import os
import shutil
import sqlite3
import tempfile
import unittest

from fieldcrypt import EncryptedDB
from fieldcrypt import crypto


class FieldCryptTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.dir, "app.db")
        self.mk_path = os.path.join(self.dir, "master.key")
        self.db = EncryptedDB.open(self.db_path, self.mk_path)

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def _insert_sample(self, n=50):
        ids = []
        for i in range(n):
            ids.append(self.db.insert("users", {
                "name": f"user{i}",
                "phone": f"138-0000-{i:04d}",
                "idcard": f"11010119900101{i:04d}x",
            }))
        return ids

    def test_encrypt_and_read(self):
        rid = self.db.insert("users", {
            "name": "张三", "phone": "138-0000-1234", "idcard": "11010119900101123X"})
        row = self.db.get("users", rid)
        self.assertEqual(row["phone"], "13800001234")       # 归一化后返回
        self.assertEqual(row["idcard"], "11010119900101123X")
        self.assertNotIn("phone_idx", row)                  # 索引列不外泄

    def test_ciphertext_at_rest(self):
        self.db.insert("users", {"name": "张三", "phone": "13800001234",
                                 "idcard": "11010119900101123X"})
        raw = sqlite3.connect(self.db_path)
        enc, = raw.execute("SELECT phone_enc FROM users").fetchone()
        self.assertNotIn("13800001234", enc)
        self.assertTrue(enc.startswith("v1.k_data_phone_"))
        # 密文里也不得有明文片段
        with open(self.db_path, "rb") as f:
            self.assertNotIn(b"13800001234", f.read())
        raw.close()

    def test_blind_index_equality_query(self):
        self._insert_sample(50)
        row = self.db.find_one_by("users", "phone", "13800000007")
        self.assertEqual(row["name"], "user7")
        # 归一化变体同样命中
        row2 = self.db.find_one_by("users", "phone", "138-0000-0007")
        self.assertEqual(row2["id"], row["id"])
        self.assertIsNone(self.db.find_one_by("users", "phone", "19999999999"))
        # 身份证号(结尾 X 大小写不敏感)
        r = self.db.find_one_by("users", "idcard", "110101199001010007X")
        self.assertEqual(r["name"], "user7")

    def test_data_key_rotation_mixed_read_write(self):
        ids = self._insert_sample(100)
        old_rows_before = self.db.all_rows("users")

        job = self.db.start_data_rotation("users", "phone")
        # 只跑一批,故意留一半旧密钥数据
        self.db.rotations.run_batch(job, batch_size=40)
        # 轮换期间写入 -> 走新密钥
        new_id = self.db.insert("users", {"name": "new", "phone": "13911112222",
                                          "idcard": "110"})
        # 新旧数据都能读
        rows = self.db.all_rows("users")
        self.assertEqual(len(rows), 101)
        self.assertEqual(rows[0]["phone"], old_rows_before[0]["phone"])
        # 新旧数据都能查
        self.assertEqual(self.db.find_one_by("users", "phone", "13800000005")["id"], ids[5])
        self.assertEqual(self.db.find_one_by("users", "phone", "13911112222")["id"], new_id)
        # 跑完
        self.db.resume_rotations()
        self.assertTrue(all(s["status"] == "done" for s in self.db.rotation_status()))
        # 全部行仍可读可查
        self.assertEqual(len(self.db.all_rows("users")), 101)
        self.assertEqual(self.db.find_one_by("users", "phone", "13800000099")["id"], ids[99])
        # 库里不再残留旧 key_id 的 phone 密文
        raw = sqlite3.connect(self.db_path)
        old_prefixes = raw.execute(
            "SELECT DISTINCT substr(phone_enc,1,20) FROM users").fetchall()
        self.assertEqual(len(old_prefixes), 1)
        raw.close()

    def test_crash_resume(self):
        """模拟进程被杀:跑几批后关闭连接,重开后续跑,结果与一次性跑完一致。"""
        self._insert_sample(300)
        job = self.db.start_data_rotation("users", "phone")
        self.db.rotations.run_batch(job, batch_size=64)   # 跑两批后"被杀"
        self.db.rotations.run_batch(job, batch_size=64)
        done_before = self.db.rotation_status()[0]["done_rows"]
        self.assertGreater(done_before, 0)
        self.db.close()  # 模拟进程退出(未跑完)

        db2 = EncryptedDB.open(self.db_path, self.mk_path)  # 重启
        pending = [j for j in db2.rotation_status() if j["status"] == "running"]
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["done_rows"], done_before)  # 检查点还在
        db2.resume_rotations(batch_size=64)
        self.assertTrue(all(s["status"] == "done" for s in db2.rotation_status()))
        rows = db2.all_rows("users")
        self.assertEqual(len(rows), 300)
        self.assertEqual(rows[7]["phone"], "13800000007")
        self.assertEqual(db2.find_one_by("users", "phone", "13800000299")["name"], "user299")
        db2.close()
        self.db = EncryptedDB.open(self.db_path, self.mk_path)  # tearDown 用

    def test_master_key_rotation(self):
        self._insert_sample(20)
        before = self.db.find_one_by("users", "phone", "13800000003")
        gen = self.db.rotate_master_key()
        self.assertEqual(gen, 2)
        # 换主密钥后数据照读照查(DEK 被重包裹,业务数据未动)
        after = self.db.find_one_by("users", "phone", "13800000003")
        self.assertEqual(before, after)
        # 重启(从文件加载新主密钥)后仍正常
        self.db.close()
        db2 = EncryptedDB.open(self.db_path, self.mk_path)
        self.assertEqual(db2.find_one_by("users", "phone", "13800000003"), before)
        db2.close()
        self.db = EncryptedDB.open(self.db_path, self.mk_path)

    def test_envelope_roundtrip(self):
        key = crypto.generate_key()
        env = crypto.encrypt_field(key, "k_data_phone_x", "hello", b"aad")
        self.assertEqual(crypto.decrypt_field(key, env, b"aad"), "hello")
        with self.assertRaises(Exception):
            crypto.decrypt_field(key, env, b"wrong-aad")
        with self.assertRaises(Exception):
            crypto.decrypt_field(crypto.generate_key(), env, b"aad")


if __name__ == "__main__":
    unittest.main(verbosity=2)
