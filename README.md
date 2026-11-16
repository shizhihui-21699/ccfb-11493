# fieldcrypto — 字段级加密的 SQLite 数据访问层

身份证号、手机号等敏感字段在落库前按字段 AES-256-GCM 加密，同时维护一个 HMAC
盲索引（blind index）支持等值查询。密钥分层：主密钥（KEK）包数据密钥（DEK），
DEK 轮换支持后台分批重加密、断点续跑、新旧密钥双读。

## 快速开始

```python
from fieldcrypto import EncryptedDB, FileMasterKeyring, Rotation
from fieldcrypto import normalize_phone, normalize_id_card

db = EncryptedDB("app.db", FileMasterKeyring("master.key"))
db.register_table(
    "users",
    plaintext_fields=["name"],
    encrypted_fields=["id_card", "phone"],
    normalizers={"phone": normalize_phone, "id_card": normalize_id_card},
)

db.insert("users", {"name": "Ada", "id_card": "110101199003074321", "phone": "138-0000-1111"})
db.find_by("users", "phone", "13800001111")   # 归一化后走盲索引，等值查询
db.get("users", 1)                            # 透明解密
```

## 设计

### 密文格式

```
MAGIC(2) | dek_id(4) | nonce(12) | AES-256-GCM(plaintext, aad=表名.字段名)
```

`dek_id` 嵌在密文头里，任何一行只要其 DEK 还在就能解密——这是轮换期间
新旧数据双读的基础。AAD 绑定「表.字段」，防止密文被搬到别的列/表重放。

### 盲索引

```
idx = HMAC-SHA256(derive_key(DEK, 表.字段), normalize(明文))[:8]
```

- 索引密钥由 DEK 派生、不落库，且按字段隔离，跨列不可关联。
- **截断长度取 8 字节（64 bit）**：千万行级别生日碰撞概率约 0.005%，且碰撞
  的代价只是多取一行、解密后比对时被过滤掉（`find_by` 始终解密验证，不会
  返回假阳性）。表特别大可以调 `cipher.INDEX_LEN` 到 12/16。
- 归一化在索引前做：手机号去非数字字符，身份证去空格转大写，保证
  "138-0000-1111" 和 "13800001111" 命中同一索引。注意 `normalize_phone`
  不剥国家码，混用 +86 前缀格式时需先自行统一。

### 密钥分层

- **主密钥（KEK）**：版本化，存 `FileMasterKeyring`（开发用；生产应换成
  KMS/HSM，DEK 只在内存中解包）。
- **数据密钥（DEK）**：按「表.字段」一个，AES-256，被主密钥包裹后存进库内
  `_deks` 表。状态机：`active → retiring → retired`。

### 轮换

- **主密钥轮换** `db.km.rotate_master()`：只重包 `_deks` 表里的 DEK，不动
  业务数据，毫秒级完成。信封加密的意义正在于此——轮换主密钥**不需要**重
  加密数据。
- **DEK 轮换**（真正需要重加密数据的场景，如密钥疑似泄露）：
  `Rotation.start(db, "users", "phone")` 生成新 DEK（旧 DEK 转 retiring），
  然后 `run_batch(n)` 分批重加密，每批一个事务并把 `last_rowid` 检查点写进
  `_rotations` 表。进程被杀后重启，`Rotation.pending_all(db)` 找回未完成的
  轮换接着跑；`Rotation.start` 本身幂等。轮换期间：
  - 读：密文自带 dek_id，新旧都能解密；
  - 查：盲索引对所有 active+retiring DEK 各算一份，`IN` 查询；
  - 写：一律用新 DEK，扫描单调前进，不会追不上。

## 基准测试

`.venv/bin/python benchmark.py 5000`（本机 M 系列 Mac，5000 行 / 500 次等值查询）：

| 操作 | 明文 | 加密 | 倍数 |
|---|---|---|---|
| 插入（逐行提交） | 39.9 µs/op | 56.9 µs/op | 1.4x |
| 插入（单事务批量） | 0.9 µs/op | 14.7 µs/op | 16.4x |
| 按手机号等值查询 | 1.9 µs/op | 11.5 µs/op | 6.0x |
| DEK 轮换重加密 | — | ~13 万行/秒 | 8 µs/行 |

结论：OLTP 逐行写入的开销被 fsync 摊薄，只慢约 40%；纯 CPU 路径（批量插入、
查询）慢 6–16 倍，但绝对值都在微秒级，5000 行全表轮换 40ms 内完成。

## 测试

```
.venv/bin/python -m pytest tests/ -q
```

覆盖：加解密往返、归一化等值查询、落库无明文、主密钥轮换后可读、DEK 轮换
全量/中途双读/写新钥、杀进程后断点续跑、错误主密钥拒绝解包。

## 生产化清单（本库未做）

- 主密钥接入 KMS/HSM；`FileMasterKeyring` 仅限开发。
- 盲索引是确定性的，会泄露「两行手机号相同」这一事实；等值查询和不可关联
  性不可兼得，如需更强保护考虑只存加密值+应用侧内存索引。
- 范围/模糊查询（LIKE）在字段级加密下天然不支持，需另行设计（如分词索引）。
- 迁移到 MySQL/PG 时把 `db.py` 的 SQL 层换掉即可，密文格式与密钥层无关。
