#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一劳永逸：微信 PC（Weixin 4.x）本地 .dat 图片解密工具。

用法:
  py -3 wechat_img.py find-key
  py -3 wechat_img.py monitor-key
  py -3 wechat_img.py decrypt <dat或目录> [-o 输出目录]

流程:
  1) 保持微信登录
  2) 在聊天里点开 2~3 张大图
  3) 立刻运行 find-key（或先开 monitor-key 再点图）
  4) 密钥写入 config.json 后，随时 decrypt 批量导出
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEPS = ROOT / ".deps"
if DEPS.exists():
    sys.path.insert(0, str(DEPS))
sys.path.insert(0, str(ROOT / "upstream"))

from decrypt_dat import (  # type: ignore
    V2_MAGIC_FULL,
    batch_decrypt,
    decrypt_dat_file,
    detect_image_format,
)
from find_image_key import (  # type: ignore
    find_xor_key,
    get_wechat_pids,
    scan_memory_for_aes_key,
    try_key,
)

CONFIG_PATH = ROOT / "config.json"
DEFAULT_OUT = ROOT / "output"


def load_config() -> dict:
    if CONFIG_PATH.exists():
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    return {}


def discover_attach() -> Path:
    cfg = load_config()
    if cfg.get("attach_dir"):
        p = Path(cfg["attach_dir"])
        if p.is_dir():
            return p
    candidates = [
        Path(r"D:\xwechat_files"),
        Path.home() / "Documents" / "xwechat_files",
        Path.home() / "Documents" / "WeChat Files",
    ]
    best: Path | None = None
    best_mtime = -1.0
    for base in candidates:
        if not base.is_dir():
            continue
        for acc in base.glob("wxid_*"):
            att = acc / "msg" / "attach"
            if att.is_dir():
                try:
                    m = att.stat().st_mtime
                except OSError:
                    m = 0
                if m > best_mtime:
                    best_mtime = m
                    best = att
    return best or Path(".")


DEFAULT_ATTACH = discover_attach()


def save_config(cfg: dict) -> None:
    CONFIG_PATH.write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"已保存密钥到: {CONFIG_PATH}")


def collect_v2_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path] if path.suffix.lower() == ".dat" else []
    files = list(path.rglob("*.dat"))
    # prefer thumbs for key derivation (smaller, recent)
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files


def find_v2_ciphertext_any(search_root: Path):
    for f in collect_v2_files(search_root)[:300]:
        try:
            header = f.read_bytes()[:31]
        except OSError:
            continue
        if header[:6] == V2_MAGIC_FULL and len(header) >= 31:
            return header[15:31], f
    return None, None


def derive_xor_key(search_root: Path) -> int:
    # attach 根目录时走 upstream；否则按任意目录统计 JPEG 尾 FF D9
    try:
        k = find_xor_key(str(search_root))
        if k is not None:
            return k
    except Exception:
        pass

    from collections import Counter

    tails: Counter[tuple[int, int]] = Counter()
    for f in collect_v2_files(search_root):
        if not f.name.endswith("_t.dat"):
            continue
        try:
            data = f.read_bytes()
        except OSError:
            continue
        if len(data) < 8 or data[:6] != V2_MAGIC_FULL:
            continue
        tails[(data[-2], data[-1])] += 1
        if sum(tails.values()) >= 32:
            break
    if not tails:
        return 0x88
    x, y = tails.most_common(1)[0][0]
    return x ^ 0xFF


def cmd_find_key(attach: Path, monitor: bool = False, interval: float = 2.5) -> int:
    ciphertext, sample = find_v2_ciphertext_any(attach)
    if ciphertext is None:
        print(f"未找到 V2 .dat：{attach}")
        return 1

    xor_key = derive_xor_key(attach)
    print(f"样本: {sample}")
    print(f"密文块: {ciphertext.hex()}")
    print(f"XOR key: 0x{xor_key:02x}")

    pids = get_wechat_pids()
    if not pids:
        print("微信未运行（找不到 Weixin.exe）")
        return 1
    print(f"Weixin PIDs: {pids}")
    print()
    if monitor:
        print("监控模式：请在微信里点开 2~3 张大图，脚本会自动抓密钥…")
        print("按 Ctrl+C 停止\n")
    else:
        print("请先在微信里点开 2~3 张大图，再运行本命令（密钥只在看图时进内存）\n")

    scan_n = 0
    try:
        while True:
            scan_n += 1
            for pid in pids:
                print(f"[扫描 #{scan_n}] PID {pid} …")
                aes_key = scan_memory_for_aes_key(pid, ciphertext)
                if aes_key:
                    # verify full decrypt on sample
                    out_test = ROOT / "output" / "_key_verify"
                    out_test.mkdir(parents=True, exist_ok=True)
                    out_path = out_test / (sample.stem + ".bin")
                    result, fmt = decrypt_dat_file(
                        str(sample), str(out_path), aes_key, xor_key
                    )
                    if result:
                        final = Path(result)
                        if fmt and final.suffix == ".bin":
                            renamed = final.with_suffix(f".{fmt}")
                            final.rename(renamed)
                            final = renamed
                        print(f"验证解密成功: {final} ({fmt})")
                    else:
                        print("警告: 找到候选密钥但样本解密失败，仍会保存")

                    cfg = load_config()
                    cfg.update(
                        {
                            "aes_key": aes_key,
                            "xor_key": f"0x{xor_key:02x}",
                            "attach_dir": str(attach),
                            "sample_file": str(sample),
                            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                        }
                    )
                    save_config(cfg)
                    print(f"\nAES key: {aes_key}")
                    print(f"XOR key: 0x{xor_key:02x}")
                    print("\n下一步: py -3 wechat_img.py decrypt <Img目录> -o output\\out")
                    return 0
            if not monitor:
                break
            print(f"尚未找到，{interval}s 后重试…（请继续在微信点大图）")
            time.sleep(interval)
            # refresh pids in case WeChat restarted
            pids = get_wechat_pids() or pids
    except KeyboardInterrupt:
        print("\n已停止监控")
        return 1

    print("\n未找到 AES 密钥。")
    print("请：微信点开几张大图 → 立刻再跑:")
    print("  py -3 wechat_img.py monitor-key")
    return 2


def resolve_keys(aes_key: str | None, xor_key: str | None):
    cfg = load_config()
    aes = aes_key or cfg.get("aes_key")
    xor = xor_key or cfg.get("xor_key") or "0x88"
    if isinstance(xor, str):
        xor_int = int(xor, 0)
    else:
        xor_int = int(xor)
    return aes, xor_int


def out_name_for(dat: Path, fmt: str, prefer_hd: bool) -> str:
    stem = dat.stem
    # keep distinction: prefer _h over mid over _t when exporting
    tag = ""
    if stem.endswith("_h"):
        stem = stem[:-2]
        tag = "_hd"
    elif stem.endswith("_t"):
        stem = stem[:-2]
        tag = "_thumb"
    else:
        tag = "_mid"
    if prefer_hd and tag == "_thumb":
        pass
    return f"{stem}{tag}.{fmt}"


def decrypt_one(dat: Path, out_dir: Path, aes_key: str, xor_key: int) -> Path | None:
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = out_dir / (dat.stem + ".bin")
    result, fmt = decrypt_dat_file(str(dat), str(tmp), aes_key, xor_key)
    if not result:
        return None
    fmt = fmt or detect_image_format(Path(result).read_bytes()[:16])
    final = out_dir / out_name_for(dat, fmt or "bin", prefer_hd=True)
    Path(result).replace(final)
    return final


def cmd_decrypt(src: Path, out_dir: Path, aes_key: str | None, xor_key: str | None,
                skip_thumbs: bool = True) -> int:
    aes, xor = resolve_keys(aes_key, xor_key)
    if not aes:
        print("没有 AES 密钥。请先运行: py -3 wechat_img.py monitor-key")
        return 1

    files = collect_v2_files(src)
    if skip_thumbs:
        files = [f for f in files if not f.name.endswith("_t.dat")]
    if not files:
        print(f"没有可解密的 .dat: {src}")
        return 1

    ok = 0
    fail = 0
    for i, f in enumerate(files, 1):
        # Prefer HD: if both .dat and _h.dat exist, decrypt both but name clearly
        path = decrypt_one(f, out_dir, aes, xor)
        if path:
            ok += 1
            print(f"[{i}/{len(files)}] OK  {path.name}")
        else:
            fail += 1
            print(f"[{i}/{len(files)}] FAIL {f.name}")

    print(f"\n完成: 成功 {ok}, 失败 {fail}")
    print(f"输出目录: {out_dir}")
    if ok:
        os.startfile(out_dir)  # noqa: S606 - Windows helper
    return 0 if ok else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="微信 .dat 图片解密（V2/V1/旧XOR）")
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("find-key", help="从微信进程内存提取一次 AES 密钥")
    f.add_argument("--attach", type=Path, default=DEFAULT_ATTACH)

    m = sub.add_parser("monitor-key", help="持续监控直到抓到密钥（推荐）")
    m.add_argument("--attach", type=Path, default=DEFAULT_ATTACH)
    m.add_argument("--interval", type=float, default=2.5)

    d = sub.add_parser("decrypt", help="解密单个 .dat 或整个目录")
    d.add_argument("src", type=Path)
    d.add_argument("-o", "--out", type=Path, default=DEFAULT_OUT)
    d.add_argument("--aes-key")
    d.add_argument("--xor-key")
    d.add_argument("--include-thumbs", action="store_true")

    sub.add_parser("show-config", help="显示已保存密钥")
    return p


def main(argv: list[str] | None = None) -> int:
    # Windows console UTF-8
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    args = build_parser().parse_args(argv)

    if args.cmd == "find-key":
        return cmd_find_key(args.attach, monitor=False)
    if args.cmd == "monitor-key":
        return cmd_find_key(args.attach, monitor=True, interval=args.interval)
    if args.cmd == "show-config":
        cfg = load_config()
        print(json.dumps(cfg, ensure_ascii=False, indent=2) if cfg else "(空)")
        return 0
    if args.cmd == "decrypt":
        return cmd_decrypt(
            args.src,
            args.out,
            args.aes_key,
            args.xor_key,
            skip_thumbs=not args.include_thumbs,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
