# -*- coding: utf-8 -*-
"""持久化密钥库: 加密保存生成过的密钥(公钥明文 + 私钥加密)与发起端信息。

私钥使用 Fernet(AES) 加密, 密钥存于 config.json 的 keystore_key 字段。
文件权限设为 600。存储位置跟随 config.json 所在目录。
"""
import base64
import json
import os
import uuid
from datetime import datetime

try:
    from cryptography.fernet import Fernet
    HAVE_FERNET = True
except Exception:
    HAVE_FERNET = False


def get_keystore_path():
    base = os.environ.get("SSHWEB_CONFIG")
    if base:
        return os.path.join(os.path.dirname(base), "keystore.json")
    if os.path.isdir("/app/data"):
        return "/app/data/keystore.json"
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "keystore.json")


KEYSTORE_PATH = get_keystore_path()


def ensure_key(cfg):
    """确保 config 里有 Fernet 密钥, 返回 base64 密钥字符串。"""
    key = (cfg.get("keystore_key") or "").strip()
    if key:
        return key
    key = Fernet.generate_key().decode("ascii")
    cfg["keystore_key"] = key
    return key


def _load():
    if not os.path.exists(KEYSTORE_PATH):
        return []
    try:
        with open(KEYSTORE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save(records):
    tmp = KEYSTORE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
    os.replace(tmp, KEYSTORE_PATH)
    try:
        os.chmod(KEYSTORE_PATH, 0o600)
    except OSError:
        pass


def _encrypt(key, plain):
    plain = plain or ""
    if not HAVE_FERNET or not key:
        return base64.b64encode(plain.encode("utf-8")).decode("ascii")
    return Fernet(key.encode("ascii")).encrypt(plain.encode("utf-8")).decode("ascii")


def _decrypt(key, token):
    token = token or ""
    if not token:
        return ""
    if not HAVE_FERNET or not key:
        try:
            return base64.b64decode(token.encode("ascii")).decode("utf-8", "replace")
        except Exception:
            return ""
    try:
        return Fernet(key.encode("ascii")).decrypt(token.encode("ascii")).decode("utf-8")
    except Exception:
        return ""


def add_record(cfg, meta, public_key, private_key):
    """追加一条记录, 返回记录 dict。meta 为发起端信息字典。"""
    key = ensure_key(cfg)
    rec = {
        "id": uuid.uuid4().hex,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_platform": meta.get("src_platform", "linux"),
        "src_host": meta.get("src_host", ""),
        "src_port": meta.get("src_port", 22),
        "src_user": meta.get("src_user", ""),
        "key_type": meta.get("key_type", "ed25519"),
        "priv_path": meta.get("priv_path", ""),
        "pub_path": meta.get("pub_path", ""),
        "public_key": (public_key or "").strip(),
        "private_key": _encrypt(key, private_key or ""),
    }
    records = _load()
    records.append(rec)
    _save(records)
    return rec


def list_records():
    """返回全部记录的元信息(不含私钥, 含公钥明文)。"""
    out = []
    for r in _load():
        out.append({
            "id": r.get("id"),
            "created_at": r.get("created_at"),
            "label": "%s@%s:%s · %s" % (r.get("src_user"), r.get("src_host"),
                                       r.get("src_port"), r.get("key_type")),
            "src_platform": r.get("src_platform"),
            "src_host": r.get("src_host"),
            "src_port": r.get("src_port"),
            "src_user": r.get("src_user"),
            "key_type": r.get("key_type"),
            "priv_path": r.get("priv_path"),
            "pub_path": r.get("pub_path"),
            "public_key": r.get("public_key"),
        })
    return out


def get_record(cfg, rec_id):
    """返回单条完整记录(含解密后的私钥), 未找到返回 None。"""
    key = ensure_key(cfg)
    for r in _load():
        if r.get("id") == rec_id:
            r2 = dict(r)
            r2["private_key"] = _decrypt(key, r.get("private_key", ""))
            return r2
    return None


def delete_record(rec_id):
    records = [r for r in _load() if r.get("id") != rec_id]
    _save(records)
