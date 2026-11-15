"""主密钥的本地文件存储(开发/演示用)。

生产环境应替换为 KMS/Vault;这里用"世代文件"保证轮换崩溃安全:
  - 文件保存全部世代 {"current": N, "keys": {"1": ..., "2": ...}}
  - 轮换顺序:先把新世代写进文件(原子 rename),再在库里重包裹并推进世代号
  - 崩溃在两者之间:文件多一个世代但库还在旧世代,加载按库里的世代取钥,可安全重试
"""
from __future__ import annotations

import json
import os
import tempfile

from . import crypto


class MasterKeyFile:
    def __init__(self, path: str):
        self.path = path

    def load_or_create(self) -> tuple[bytes, int]:
        if not os.path.exists(self.path):
            return self._fresh()
        with open(self.path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        return crypto.b64d(doc["keys"][str(doc["current"])]), int(doc["current"])

    def key_for_generation(self, gen: int) -> bytes:
        with open(self.path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        return crypto.b64d(doc["keys"][str(gen)])

    def add_generation(self) -> tuple[bytes, int]:
        """追加新世代并原子落盘,返回 (new_master_key, new_gen)。"""
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                doc = json.load(f)
        else:
            doc = {"current": 0, "keys": {}}
        new_gen = int(doc["current"]) + 1
        new_key = crypto.generate_key()
        doc["keys"][str(new_gen)] = crypto.b64e(new_key)
        doc["current"] = new_gen
        self._atomic_write(doc)
        return new_key, new_gen

    def _fresh(self) -> tuple[bytes, int]:
        key = crypto.generate_key()
        self._atomic_write({"current": 1, "keys": {"1": crypto.b64e(key)}})
        os.chmod(self.path, 0o600)
        return key, 1

    def _atomic_write(self, doc: dict) -> None:
        d = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".masterkey.")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(doc, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
