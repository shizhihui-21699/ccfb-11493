"""fieldcrypto: field-level encryption data-access layer for SQLite.

    from fieldcrypto import EncryptedDB, FileMasterKeyring, normalize_phone, normalize_id_card

    db = EncryptedDB("app.db", FileMasterKeyring("master.key"))
    db.register_table("users",
                      plaintext_fields=["name"],
                      encrypted_fields=["id_card", "phone"],
                      normalizers={"phone": normalize_phone, "id_card": normalize_id_card})
    db.insert("users", {"name": "Ada", "id_card": "11010119900307xxxx", "phone": "138-0000-1111"})
    db.find_by("users", "phone", "13800001111")
"""

from .cipher import INDEX_LEN, CipherError
from .db import EncryptedDB, normalize_default, normalize_id_card, normalize_phone
from .keys import FileMasterKeyring, KeyManager, MasterKeyError
from .rotation import Rotation

__all__ = [
    "EncryptedDB",
    "FileMasterKeyring",
    "KeyManager",
    "Rotation",
    "CipherError",
    "MasterKeyError",
    "INDEX_LEN",
    "normalize_phone",
    "normalize_id_card",
    "normalize_default",
]
