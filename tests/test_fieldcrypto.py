import sqlite3

import pytest

from fieldcrypto import (
    EncryptedDB,
    FileMasterKeyring,
    MasterKeyError,
    Rotation,
    normalize_id_card,
    normalize_phone,
)

USERS = dict(
    plaintext_fields=["name"],
    encrypted_fields=["id_card", "phone"],
    normalizers={"phone": normalize_phone, "id_card": normalize_id_card},
)

SAMPLE = [
    {"name": "Ada", "id_card": "110101199003074321", "phone": "138-0000-1111"},
    {"name": "Bob", "id_card": "31010419881112002x", "phone": "139-1111-2222"},
    {"name": "Cid", "id_card": "440305199505153333", "phone": "13700003333"},
]


@pytest.fixture
def db(tmp_path):
    d = EncryptedDB(tmp_path / "app.db", FileMasterKeyring(tmp_path / "master.key"))
    d.register_table("users", **USERS)
    yield d
    d.close()


def reopen(tmp_path):
    d = EncryptedDB(tmp_path / "app.db", FileMasterKeyring(tmp_path / "master.key"))
    d.register_table("users", **USERS)
    return d


def test_insert_get_roundtrip(db):
    rid = db.insert("users", SAMPLE[0])
    row = db.get("users", rid)
    assert row["name"] == "Ada"
    assert row["id_card"] == "110101199003074321"
    assert row["phone"] == "138-0000-1111"


def test_ciphertext_at_rest(db, tmp_path):
    db.insert("users", SAMPLE[0])
    db.close()
    raw = sqlite3.connect(tmp_path / "app.db")
    blob, idx = raw.execute("SELECT phone_enc, phone_idx FROM users").fetchone()
    assert b"138" not in bytes(blob) and b"0000" not in bytes(blob)
    assert len(idx) == 8  # truncated blind index
    # no plaintext anywhere in the file
    assert b"138-0000-1111" not in (tmp_path / "app.db").read_bytes()


def test_find_by_normalizes(db):
    db.insert("users", SAMPLE[0])
    assert db.find_by("users", "phone", "13800001111")[0]["name"] == "Ada"
    assert db.find_by("users", "phone", "138-0000-1111")[0]["name"] == "Ada"
    assert db.find_by("users", "phone", "19999999999") == []
    assert db.find_by("users", "id_card", " 110101199003074321 ")[0]["name"] == "Ada"


def test_update_reencrypts(db):
    rid = db.insert("users", SAMPLE[0])
    db.update("users", rid, phone="136-1111-0000")
    assert db.find_by("users", "phone", "13800001111") == []
    assert db.get("users", rid)["phone"] == "136-1111-0000"


def test_master_rotation_keeps_data_readable(db, tmp_path):
    for s in SAMPLE:
        db.insert("users", s)
    new_version = db.km.rotate_master()
    assert new_version == 2
    assert db.find_by("users", "phone", "13800001111")[0]["name"] == "Ada"
    # old master key alone can no longer unwrap: simulate by fresh KeyManager
    # cache is warm in this process, so verify via a reopened DB
    db.close()
    db2 = reopen(tmp_path)
    assert db2.find_by("users", "id_card", "31010419881112002X")[0]["name"] == "Bob"
    db2.close()


def test_dek_rotation_full(db):
    for s in SAMPLE:
        db.insert("users", s)
    rot = Rotation.start(db, "users", "phone")
    total = rot.run_to_completion(batch_size=2)
    assert total == 3
    assert rot.done()
    assert db.find_by("users", "phone", "13800001111")[0]["name"] == "Ada"
    assert db.find_by("users", "phone", "13700003333")[0]["name"] == "Cid"
    # every row on the new DEK now
    keys = {r[0] for r in db.conn.execute("SELECT phone_key FROM users")}
    assert keys == {rot.new_dek}


def test_rotation_dual_read_midway(db):
    ids = [db.insert("users", s) for s in SAMPLE]
    rot = Rotation.start(db, "users", "phone")
    rot.run_batch(1)  # only first row re-encrypted
    assert not rot.done()
    # both generations readable and queryable
    assert db.get("users", ids[0])["phone"] == "138-0000-1111"
    assert db.get("users", ids[2])["phone"] == "13700003333"
    assert db.find_by("users", "phone", "13800001111")[0]["id"] == ids[0]
    assert db.find_by("users", "phone", "13911112222")[0]["id"] == ids[1]
    # new writes during rotation go to the new DEK and are found too
    new_id = db.insert("users", {"name": "Eve", "id_card": "1", "phone": "15012345678"})
    assert db.conn.execute(
        "SELECT phone_key FROM users WHERE id = ?", (new_id,)
    ).fetchone()[0] == rot.new_dek
    assert db.find_by("users", "phone", "15012345678")[0]["id"] == new_id
    rot.run_to_completion()
    assert db.count("users") == 4


def test_rotation_resume_after_kill(db, tmp_path):
    for s in SAMPLE:
        db.insert("users", s)
    rot = Rotation.start(db, "users", "phone")
    rot.run_batch(1)  # one batch committed, then "process killed"
    db.close()

    db2 = reopen(tmp_path)  # fresh process, cold key cache
    pending = Rotation.pending_all(db2)
    assert len(pending) == 1
    assert pending[0].last_rowid > 0
    # data still fully readable before resuming
    assert db2.find_by("users", "phone", "13911112222")[0]["name"] == "Bob"
    pending[0].run_to_completion(batch_size=1)
    assert db2.count("users") == 3
    assert db2.find_by("users", "phone", "13700003333")[0]["name"] == "Cid"
    assert Rotation.pending_all(db2) == []
    db2.close()


def test_rotation_start_is_idempotent(db):
    db.insert("users", SAMPLE[0])
    r1 = Rotation.start(db, "users", "phone")
    r2 = Rotation.start(db, "users", "phone")
    assert (r1.old_dek, r1.new_dek) == (r2.old_dek, r2.new_dek)


def test_wrong_master_key_rejected(db, tmp_path):
    db.insert("users", SAMPLE[0])
    db.close()
    other = tmp_path / "other"
    other.mkdir()
    (other / "app.db").write_bytes((tmp_path / "app.db").read_bytes())
    db2 = EncryptedDB(other / "app.db", FileMasterKeyring(other / "master.key"))
    db2.register_table("users", **USERS)
    with pytest.raises(MasterKeyError):
        db2.get("users", 1)
    db2.close()
