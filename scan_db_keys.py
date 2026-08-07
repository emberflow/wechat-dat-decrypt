# -*- coding: utf-8 -*-
"""扫描 Weixin.exe 内存提取 SQLCipher 密钥。

匹配:
  - ASCII / UTF-16LE: x'<64~192 hex>'
  - 用本地 .db 文件头 salt 在内存中定位邻近 32 字节 key
"""
from __future__ import annotations

import ctypes
import json
import re
import struct
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "config.json"
WX = Path(r"D:\xwechat_files\wxid_07no4yy4gx0j22_03fb\db_storage")

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

RE_ASCII = re.compile(rb"x'([0-9a-fA-F]{64,192})'")
# UTF-16LE: x ' 0 9 ... '
RE_UTF16 = re.compile(
    rb"x\x00'\x00((?:[0-9a-fA-F]\x00){64,192})'\x00"
)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


kernel32 = ctypes.windll.kernel32


def get_pids() -> list[int]:
    r = subprocess.run(
        ["tasklist.exe", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
    )
    pids = []
    for line in r.stdout.strip().splitlines():
        if "Weixin.exe" in line:
            parts = line.strip('"').split('","')
            if len(parts) >= 2:
                pids.append(int(parts[1]))
    return pids


def readable(protect: int) -> bool:
    if protect in (PAGE_NOACCESS,) or (protect & PAGE_GUARD):
        return False
    return (
        protect
        & (
            PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
        )
    ) != 0


def load_salts() -> dict[bytes, str]:
    """salt(16B) -> db path"""
    out = {}
    for db in WX.rglob("*.db"):
        if db.name.endswith(".decrypted.db"):
            continue
        try:
            salt = db.read_bytes()[:16]
        except OSError:
            continue
        if len(salt) == 16:
            out[salt] = str(db)
    return out


def verify_key(db_path: str, enc_key_hex: str) -> bool:
    """HMAC check page1 with SQLCipher-ish params used by decrypt_db.py"""
    import hashlib
    import hmac

    KEY_SZ = 32
    PAGE_SZ = 4096
    SALT_SZ = 16
    IV_SZ = 16
    HMAC_SZ = 64
    RESERVE_SZ = (IV_SZ + HMAC_SZ + 15) // 16 * 16
    try:
        data = Path(db_path).read_bytes()
        rawkey = bytes.fromhex(enc_key_hex[:64])
    except Exception:
        return False
    if len(data) < PAGE_SZ:
        return False
    salt = data[:SALT_SZ]
    page1 = data[SALT_SZ:PAGE_SZ]
    mac_salt = bytes(x ^ 0x3A for x in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", rawkey, mac_salt, 2, KEY_SZ)
    h = hmac.new(mac_key, digestmod="sha512")
    h.update(page1[: -RESERVE_SZ + IV_SZ])
    h.update(bytes.fromhex("01 00 00 00"))
    return h.digest() == page1[-RESERVE_SZ + IV_SZ :][:HMAC_SZ]


def scan_pid(pid: int, salts: dict[bytes, str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    h = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        print(f"  PID {pid}: OpenProcess failed err={ctypes.GetLastError()}")
        return counts
    try:
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        regions = []
        while address < 0x7FFFFFFFFFFF:
            if (
                kernel32.VirtualQueryEx(
                    h, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
                )
                == 0
            ):
                break
            if (
                mbi.State == MEM_COMMIT
                and readable(mbi.Protect)
                and mbi.RegionSize <= 80 * 1024 * 1024
            ):
                regions.append((mbi.BaseAddress, mbi.RegionSize))
            nxt = address + mbi.RegionSize
            if nxt <= address:
                break
            address = nxt
        print(f"  PID {pid}: readable regions={len(regions)}")

        salt_hits = 0
        for idx, (base, size) in enumerate(regions):
            if idx % 300 == 0:
                print(f"    {idx}/{len(regions)}", end="\r", flush=True)
            buf = ctypes.create_string_buffer(size)
            nread = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(
                h, ctypes.c_void_p(base), buf, size, ctypes.byref(nread)
            )
            if not ok or nread.value < 70:
                continue
            data = buf.raw[: nread.value]

            salt_hex_map = {salt.hex(): db for salt, db in salts.items()}

            for m in RE_ASCII.finditer(data):
                hx = m.group(1).decode("ascii")
                enc = hx[:64]
                counts[enc] = counts.get(enc, 0) + 1
                # x'<key64><salt32>' 且 salt 命中本地库 → 高置信
                if len(hx) >= 96:
                    sh = hx[64:96]
                    if sh in salt_hex_map:
                        counts[enc] = counts.get(enc, 0) + 1000
                        print(
                            f"\n    *** x'key+salt' match {Path(salt_hex_map[sh]).name}: {enc[:16]}…"
                        )
            for m in RE_UTF16.finditer(data):
                raw = m.group(1)
                hx = raw.decode("utf-16le")
                enc = hx[:64]
                if re.fullmatch(r"[0-9a-fA-F]{64,192}", hx):
                    counts[enc] = counts.get(enc, 0) + 1
                    if len(hx) >= 96 and hx[64:96] in salt_hex_map:
                        counts[enc] = counts.get(enc, 0) + 1000
                        print(
                            f"\n    *** utf16 key+salt match {Path(salt_hex_map[hx[64:96]]).name}: {enc[:16]}…"
                        )

            # salt 二进制邻近：尝试前后对齐的 32 字节作为 enc_key
            for salt, db_path in salts.items():
                pos = 0
                while True:
                    i = data.find(salt, pos)
                    if i < 0:
                        break
                    salt_hits += 1
                    candidates = []
                    if i >= 32:
                        candidates.append(data[i - 32 : i])
                    if i >= 48:
                        candidates.append(data[i - 48 : i - 16])
                    if i + 16 + 32 <= len(data):
                        candidates.append(data[i + 16 : i + 48])
                    # 常见：中间夹 8/16 字节头
                    for gap in (8, 16, 24, 40, 64):
                        if i >= 32 + gap:
                            candidates.append(data[i - 32 - gap : i - gap])
                    for cand in candidates:
                        if len(cand) != 32 or cand == salt or cand == b"\x00" * 32:
                            continue
                        enc = cand.hex()
                        if verify_key(db_path, enc):
                            counts[enc] = counts.get(enc, 0) + 1000
                            print(
                                f"\n    *** binary key near salt {Path(db_path).name}: {enc[:16]}…"
                            )
                    pos = i + 1
        print(f"\n    salt_binary_hits={salt_hits}")
    finally:
        kernel32.CloseHandle(h)
    return counts


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    pids = get_pids()
    if not pids:
        print("微信未运行")
        return 1
    print(f"PIDs: {pids}")
    salts = load_salts()
    print(f"loaded {len(salts)} db salts for proximity search")
    # 先用 contact.db 等小库 salt，减少邻近扫描开销
    priority = {}
    for salt, path in salts.items():
        name = Path(path).name
        if name in {"contact.db", "session.db", "message_0.db", "hardlink.db"}:
            priority[salt] = path
    if not priority:
        priority = dict(list(salts.items())[:8])
    print(f"priority salts: {len(priority)}")

    all_counts: dict[str, int] = {}
    for pid in pids:
        part = scan_pid(pid, priority)
        for k, c in part.items():
            all_counts[k] = all_counts.get(k, 0) + c

    # 最终用所有 priority db 验证一遍候选
    verified = []
    for k, c in sorted(all_counts.items(), key=lambda x: -x[1]):
        for db in priority.values():
            if verify_key(db, k):
                verified.append((k, c, Path(db).name))
                break

    if verified:
        print(f"\n验证通过 {len(verified)} 个密钥:")
        for k, c, dbn in verified[:10]:
            print(f"  freq={c} db={dbn} key={k}")
        keys = [k for k, _, _ in verified]
    elif all_counts:
        print(f"\n未验证通过，但有 {len(all_counts)} 候选（将尝试解密）:")
        keys = [k for k, _ in sorted(all_counts.items(), key=lambda x: -x[1])[:30]]
        for k in keys[:10]:
            print(f"  {k}")
    else:
        print("\n未找到密钥。")
        print("请右键「以管理员身份运行」: D:\\Projects\\wechat-dat-decrypt\\抓库密钥_管理员.bat")
        print("并确保微信已登录；可先在微信里随便打开几个聊天触发数据库加载。")
        return 2

    with open(ROOT / "found_keys.txt", "w", encoding="utf-8") as f:
        for i, k in enumerate(keys):
            f.write(f"{i}\t1\t{k}\n")
    cfg = {}
    if CONFIG.exists():
        cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    cfg["db_keys"] = keys[:20]
    cfg["db_key"] = keys[0]
    CONFIG.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("已写入 found_keys.txt / config.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
