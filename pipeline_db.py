# -*- coding: utf-8 -*-
"""扫描数据库密钥 → 解密关键库到 decrypted/（不污染微信目录）。"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEPS = ROOT / ".deps"
sys.path.insert(0, str(DEPS))
sys.path.insert(0, str(ROOT / "upstream"))

from decrypt_db import decrypt_db, try_decrypt_with_keys  # noqa: E402
from decrypt_engine import scan_keys_from_memory  # noqa: E402

WX_ACCOUNT = Path(r"D:\xwechat_files\wxid_07no4yy4gx0j22_03fb")
OUT_DIR = ROOT / "decrypted"
CONFIG = ROOT / "config.json"

# 只解密这些关键库，加快速度
TARGETS = [
    WX_ACCOUNT / "db_storage" / "contact" / "contact.db",
    WX_ACCOUNT / "db_storage" / "session" / "session.db",
    WX_ACCOUNT / "db_storage" / "hardlink" / "hardlink.db",
    WX_ACCOUNT / "db_storage" / "message" / "message_0.db",
    WX_ACCOUNT / "db_storage" / "message" / "message_1.db",
    WX_ACCOUNT / "db_storage" / "message" / "message_2.db",
    WX_ACCOUNT / "db_storage" / "message" / "message_resource.db",
    WX_ACCOUNT / "db_storage" / "message" / "media_0.db",
]


def load_saved_keys() -> list[str]:
    keys = []
    cfg = {}
    if CONFIG.exists():
        cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
        if cfg.get("db_key"):
            keys.append(cfg["db_key"])
        for k in cfg.get("db_keys") or []:
            if k not in keys:
                keys.append(k)
    kf = ROOT / "found_keys.txt"
    if kf.exists():
        for line in kf.read_text(encoding="utf-8").splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 3 and parts[2] not in keys:
                keys.append(parts[2])
    return keys


def save_keys(keys: list[str], working: str | None) -> None:
    cfg = {}
    if CONFIG.exists():
        cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    if working:
        cfg["db_key"] = working
    cfg["db_keys"] = keys[:20]
    CONFIG.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with open(ROOT / "found_keys.txt", "w", encoding="utf-8") as f:
        for i, k in enumerate(keys):
            f.write(f"{i}\t?\t{k}\n")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    keys = load_saved_keys()
    print(f"已有密钥候选: {len(keys)}")
    print("从微信进程扫描密钥…")
    scanned = scan_keys_from_memory()
    for k in scanned:
        if k not in keys:
            keys.append(k)
    print(f"合计候选: {len(keys)}")
    if not keys:
        print("未找到密钥。请确认微信已登录，必要时以管理员运行。")
        return 1

    working = None
    ok = fail = 0
    for db in TARGETS:
        if not db.exists():
            print(f"  [SKIP] 不存在 {db}")
            continue
        out = OUT_DIR / db.name.replace(".db", ".decrypted.db")
        # 先试已知 working key
        order = list(keys)
        if working and working in order:
            order.remove(working)
            order.insert(0, working)

        decrypted = False
        for hex_key in order:
            try:
                raw = bytes.fromhex(hex_key)
            except ValueError:
                continue
            # decrypt_db 会写到 output_path
            result = decrypt_db(str(db), raw, str(out))
            if result:
                print(f"  [OK] {db.name} -> {out.name} (key={hex_key[:16]}…)")
                working = hex_key
                ok += 1
                decrypted = True
                break
            # 失败时可能写出坏文件
            if out.exists() and out.stat().st_size > 0:
                # decrypt_db only writes on success after HMAC check returns None early
                pass
        if not decrypted:
            print(f"  [FAIL] {db.name}")
            fail += 1
            if out.exists():
                out.unlink(missing_ok=True)

    save_keys(keys, working)
    print(f"\n完成: OK={ok} FAIL={fail}")
    if working:
        print(f"工作密钥已写入 config.json: {working[:16]}…")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
