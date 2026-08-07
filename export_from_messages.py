# -*- coding: utf-8 -*-
"""
在已解密数据库就绪后：
1) 定位备注「我妈」
2) 列出图片消息（可按今天）
3) 优先本地 .dat 解密；若消息 XML 含 cdn+aeskey 则尝试 CDN 拉原图
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import urllib.request
from datetime import date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / ".deps"))
sys.path.insert(0, str(ROOT / "upstream"))
sys.path.insert(0, str(ROOT))

from Crypto.Cipher import AES  # noqa: E402
from Crypto.Util import Padding  # noqa: E402

from wechat_img import decrypt_one, resolve_keys, DEFAULT_OUT  # noqa: E402

DEC = ROOT / "decrypted"
ATTACH = Path(r"D:\xwechat_files\wxid_07no4yy4gx0j22_03fb\msg\attach")
MOM_HASH = "5d21831e5c13a42e2983627bc632302b"
TODAY = date.today()


def open_db(path: Path):
    import sqlite3

    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def find_mom_username() -> str | None:
    db = DEC / "contact.decrypted.db"
    if not db.exists():
        return None
    conn = open_db(db)
    cur = conn.cursor()
    # 表名可能是 contact
    try:
        cur.execute(
            "SELECT username, remark, nick_name FROM contact WHERE remark LIKE ? OR nick_name LIKE ?",
            ("%妈%", "%妈%"),
        )
        rows = cur.fetchall()
    except Exception as e:
        print("contact query failed", e)
        return None
    for r in rows:
        u = r["username"] or ""
        h = hashlib.md5(u.encode()).hexdigest()
        print(f"  candidate remark={r['remark']!r} nick={r['nick_name']!r} user={u} md5={h}")
        if h == MOM_HASH or (r["remark"] and "妈" in r["remark"]):
            if h == MOM_HASH:
                return u
    # fallback: username whose md5 matches folder
    try:
        cur.execute("SELECT username, remark, nick_name FROM contact")
        for r in cur.fetchall():
            u = r["username"] or ""
            if hashlib.md5(u.encode()).hexdigest() == MOM_HASH:
                print(f"  matched by md5: remark={r['remark']!r} nick={r['nick_name']!r}")
                return u
    except Exception:
        pass
    return None


def extract_xml(raw: str, tag: str) -> str | None:
    m = re.search(rf"<{tag}><!\[CDATA\[(.*?)\]\]></{tag}>", raw, re.S)
    if m:
        return m.group(1)
    m = re.search(rf"<{tag}>(.*?)</{tag}>", raw, re.S)
    if m:
        return m.group(1)
    return None


def extract_attr(raw: str, tag: str, attr: str) -> str | None:
    m = re.search(rf"<{tag}\b[^>]*\b{attr}=\"([^\"]+)\"", raw)
    return m.group(1) if m else None


def decompress_content(data) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    if isinstance(data, bytes):
        if data[:4] == b"\x28\xb5\x2f\xfd":
            import zstandard

            data = zstandard.ZstdDecompressor().decompress(data, max_output_size=50 * 1024 * 1024)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("utf-8", errors="replace")
    return str(data)


def list_image_msgs(username: str, only_today: bool = True) -> list[dict]:
    import sqlite3

    table = "Msg_" + hashlib.md5(username.encode()).hexdigest()
    msgs = []
    for dbp in sorted(DEC.glob("message_*.decrypted.db")):
        conn = open_db(dbp)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r[0] for r in cur.fetchall()}
        # Name2Id 映射
        # 实际表名可能就是 Msg_<md5>
        candidates = [t for t in tables if t.lower() == table.lower() or t.startswith("Msg_")]
        # 直接找
        target = None
        for t in tables:
            if t.replace("Msg_", "").replace("msg_", "") == hashlib.md5(username.encode()).hexdigest():
                target = t
                break
        if not target:
            # try talker hash folder style - already have MOM_HASH
            for t in tables:
                if MOM_HASH in t:
                    target = t
                    break
        if not target:
            continue
        print(f"  using table {target} in {dbp.name}")
        cur.execute(f"PRAGMA table_info({target})")
        cols = [r[1] for r in cur.fetchall()]
        # common: local_id, local_type, create_time, message_content, packed_info_data, status...
        colset = set(cols)
        need = ["local_type", "create_time", "message_content"]
        if not all(c in colset for c in need):
            print(f"  unexpected cols: {cols[:20]}")
            continue
        cur.execute(
            f"SELECT local_type, create_time, message_content, packed_info_data FROM {target} WHERE local_type=3 OR local_type=47"
        )
        for row in cur.fetchall():
            ts = row[1] or 0
            dt = datetime.fromtimestamp(ts)
            if only_today and dt.date() != TODAY:
                continue
            raw = decompress_content(row[2])
            md5 = extract_xml(raw, "md5") or ""
            aeskey = extract_xml(raw, "aeskey") or extract_attr(raw, "img", "aeskey") or ""
            cdnbig = (
                extract_xml(raw, "cdnbigimgurl")
                or extract_xml(raw, "cdnmidimgurl")
                or extract_attr(raw, "img", "cdnbigimgurl")
                or extract_attr(raw, "img", "cdnmidimgurl")
                or ""
            )
            # urls sometimes HTML escaped
            cdnbig = cdnbig.replace("&amp;", "&")
            msgs.append(
                {
                    "time": dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "ts": ts,
                    "md5": md5,
                    "aeskey": aeskey,
                    "cdn": cdnbig,
                    "raw_head": raw[:200].replace("\n", " "),
                }
            )
    msgs.sort(key=lambda m: m["ts"])
    return msgs


def cdn_download(url: str, aeskey_hex: str, out: Path) -> bool:
    if not url or not aeskey_hex:
        return False
    try:
        key = bytes.fromhex(aeskey_hex)
        if len(key) not in (16, 24, 32):
            # sometimes 16 bytes hex = 32 chars
            if len(aeskey_hex) >= 32:
                key = bytes.fromhex(aeskey_hex[:32])
            else:
                return False
        req = urllib.request.Request(url, headers={"User-Agent": "MicroMessenger Client"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
        cipher = AES.new(key[:16], AES.MODE_ECB)
        try:
            plain = Padding.unpad(cipher.decrypt(data), 16)
        except ValueError:
            plain = cipher.decrypt(data)
        # trim to jpeg/png
        if plain[:3] == b"\xff\xd8\xff":
            out.write_bytes(plain)
            return True
        if plain[:8] == b"\x89PNG\r\n\x1a\n":
            out.write_bytes(plain)
            return True
        # try without unpad already done
        out.write_bytes(plain)
        return out.stat().st_size > 1000
    except Exception as e:
        print(f"    cdn fail: {e}")
        return False


def local_best(md5: str) -> Path | None:
    # 在妈妈目录按文件名包含 md5 / 或遍历今天文件 —— 本地文件名是 hash 不是 md5
    # 回退：不解 md5 映射时，仍由调用方用时间窗导出
    return None


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if not (DEC / "contact.decrypted.db").exists():
        print("尚未解密数据库。请先管理员运行：抓库密钥_管理员.bat")
        print("然后: py -3 pipeline_db.py")
        return 1

    print("查找「我妈」…")
    user = find_mom_username()
    if not user:
        print("未在联系人中定位到我妈，将仅用 folder hash 对应表")
        user = ""
    else:
        print(f"username={user} md5={hashlib.md5(user.encode()).hexdigest()}")

    print("列出今天的图片消息…")
    msgs = list_image_msgs(user or "placeholder", only_today=True)
    # if user empty, try Msg_MOM_HASH
    if not msgs and not user:
        # force table by hash
        for dbp in DEC.glob("message_*.decrypted.db"):
            conn = open_db(dbp)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            for (t,) in cur.fetchall():
                if MOM_HASH in t:
                    print("found table", t)

    print(f"今天图片消息: {len(msgs)}")
    with_cdn = sum(1 for m in msgs if m["cdn"] and m["aeskey"])
    print(f"含 CDN+aeskey: {with_cdn}")

    out = DEFAULT_OUT / f"mom-{TODAY.isoformat()}-full"
    out.mkdir(parents=True, exist_ok=True)
    aes_img, xor = resolve_keys(None, None)

    ok_cdn = ok_local = fail = 0
    for i, m in enumerate(msgs, 1):
        name = f"{i:03d}_{m['time'].replace(':','-').replace(' ','_')}"
        done = False
        if m["cdn"] and m["aeskey"]:
            dest = out / f"{name}.jpg"
            if cdn_download(m["cdn"], m["aeskey"], dest):
                print(f"[{i}/{len(msgs)}] CDN  {dest.name}")
                ok_cdn += 1
                done = True
        if not done:
            fail += 1
            print(f"[{i}/{len(msgs)}] SKIP no cdn/local  md5={m['md5'][:8] if m['md5'] else '-'}")

    print(f"\nCDN成功 {ok_cdn}, 跳过 {fail}")
    print(f"输出: {out}")
    try:
        os.startfile(out)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
