# fieldcrypt — SQLite 字段级加密数据访问库

用户表里的手机号、身份证不再落明文:写入时按字段 AES-256-GCM 加密,同时维护一个
HMAC 盲索引支撑等值查询;密钥两层结构,主密钥包数据密钥,支持在线轮换。

## 快速开始

```bash
python3 -m venv .venv && .venv/bin/pip install cryptography
.venv/bin/python test_fieldcrypt.py   # 功能测试(含崩溃续跑模拟)
.venv/bin/python benchmark.py         # 基准测试
```

```python
from fieldcrypt import EncryptedDB

db = EncryptedDB.open("app.db", master_key_path="master.key")

db.insert("users", {"name": "张三", "phone": "138-0000-1234", "idcard": "110...X"})
row = db.find_one_by("users", "phone", "13800001234")   # 盲索引等值查询

db.rotate_master_key()                    # 主密钥轮换:只重包裹 DEK,秒级
db.start_data_rotation("users", "phone")  # 数据密钥轮换:登记后台重加密任务
db.resume_rotations()                     # 跑到完;进程被杀后重启再调一次即续跑
```

## 设计

### 信封格式

每个密文自带密钥版本:`v1.<key_id>.<base64(nonce‖ciphertext‖tag)>`。
解密时按 `key_id` 找密钥,因此**新旧密钥的数据天然共存可读** —— 这是轮换期间
业务无感的基础。AAD 绑定 `表名:字段名`,防止密文被搬到别的字段/表重放。

### 盲索引

`HMAC-SHA256(index_key, field‖0x00‖归一化值)`,**截断到 8 字节(64 bit)**。

- 截断取舍:生日界下约 2^32 行才有 50% 碰撞,千万级用户表误命中概率可忽略;
  且查询侧解密后会做一次明文比对兜底,截断只影响索引选择性,不影响正确性。
- 索引密钥独立于数据密钥:数据密钥轮换时索引不变,查询全程无感。
- 归一化(手机号去非数字、身份证去空格大写)在索引和写入前各做一次,
  `138-0000-1234` 与 `13800001234` 命中同一索引。
- 只支持等值查询。范围/模糊查询与确定性加密天然冲突,需要时得另寻方案
  (如 ORE,但泄漏更多,不建议)。

### 密钥分层与轮换

```
主密钥 (KEK, 本地文件/KMS)
   └── 包裹 → 数据密钥 DEK(_keys 表,按字段一把,版本化)
   └── 包裹 → 索引密钥(_keys 表,按字段一把,长期不变)
```

- **主密钥轮换** = 重新包裹所有 DEK,单事务完成,不碰业务数据,毫秒级。
  主密钥文件带世代号,先落新文件再改库,崩溃在两者之间可按库的世代号恢复重试。
- **数据密钥轮换** = 新 DEK 置 active(写入立即用新钥),旧钥转 retiring,
  后台任务按 rowid 分批重加密,完成后旧钥转 retired(保留可解密,不删除)。

### 崩溃续跑

- 进度落库 `_rotation_state(last_rowid, done_rows, status)`,**每批一个事务:
  行更新和检查点推进一起提交**,崩溃最多重做一批,不会重加密出重复/损坏数据。
- 进程被杀后重启,`resume_rotations()` 扫描 running 状态的任务从断点继续。
- 轮换期间的并发写入走新密钥;重加密的 UPDATE 带旧信封值做乐观并发检查,
  行被并发改动则跳过(新写入本来就用新钥,不会漏)。

## 基准(2 万行,M 系列 Mac,本机单次跑)

| 操作 | 明文 | 加密 | 倍数 |
|---|---|---|---|
| 批量写入 | ~134 万行/s | ~7 万行/s | ~19x |
| 手机号等值查询(中位) | 4.4 µs | 10.8 µs | ~2.5x |
| 不用盲索引全表解密扫描(对照) | — | 90 ms/次 | ~8000x |
| 数据密钥轮换(重加密 2 万行) | — | 0.10 s | ~19 万行/s |

结论:**查询侧代价很小(微秒级,约 2.5x)**,盲索引相对全表解密是数量级差异;
写入是 CPU 密集活,单条比明文慢,批量事务后约 19x,对在线业务通常可接受。

## 文件

```
fieldcrypt/
  crypto.py     AES-GCM、密钥包裹、盲索引
  keystore.py   DEK 存取/状态机/主密钥重包裹
  masterkey.py  主密钥世代文件(生产应换 KMS)
  rotation.py   分批重加密 + 断点续跑
  db.py         EncryptedDB 门面
test_fieldcrypt.py   benchmark.py
```

## 已知边界

- 主密钥用本地文件只是开发兜底,生产接 KMS/Vault;文件权限 0600。
- 等值查询会泄漏"相等性"和访问频次(所有确定性盲索引的通病),敏感场景
  评估是否需要加访问控制/限流。
- 索引密钥轮换 = 全量重建索引列,框架支持但本库未做界面化,需要时按
  rotation 的模式加一个 idx 重建任务即可。
- 范围查询、LIKE、排序不支持(字段级加密的固有限制)。
