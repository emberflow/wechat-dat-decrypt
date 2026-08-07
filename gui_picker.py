#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""桌面入口：选择聊天 → 选择月份 → 解密图片。"""

from __future__ import annotations

import os
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, simpledialog, ttk

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wechat_img import (  # noqa: E402
    CONFIG_PATH,
    DEFAULT_ATTACH,
    DEFAULT_OUT,
    cmd_decrypt,
    load_config,
    save_config,
)


def scan_chats(attach: Path) -> list[dict]:
    rows: list[dict] = []
    if not attach.is_dir():
        return rows
    for chat_dir in attach.iterdir():
        if not chat_dir.is_dir() or len(chat_dir.name) < 8:
            continue
        months: list[str] = []
        img_count = 0
        hd_count = 0
        last_mtime = 0.0
        for month_dir in chat_dir.iterdir():
            if not month_dir.is_dir():
                continue
            img_dir = month_dir / "Img"
            if not img_dir.is_dir():
                continue
            months.append(month_dir.name)
            for f in img_dir.glob("*.dat"):
                try:
                    st = f.stat()
                except OSError:
                    continue
                img_count += 1
                if f.name.endswith("_h.dat"):
                    hd_count += 1
                if st.st_mtime > last_mtime:
                    last_mtime = st.st_mtime
        if img_count == 0:
            continue
        months.sort(reverse=True)
        rows.append(
            {
                "id": chat_dir.name,
                "path": chat_dir,
                "months": months,
                "img_count": img_count,
                "hd_count": hd_count,
                "last_mtime": last_mtime,
                "last_text": datetime.fromtimestamp(last_mtime).strftime("%Y-%m-%d %H:%M")
                if last_mtime
                else "-",
            }
        )
    rows.sort(key=lambda r: r["last_mtime"], reverse=True)
    return rows


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("微信图片解密")
        self.geometry("820x560")
        self.minsize(720, 480)

        cfg = load_config()
        self.attach = Path(cfg.get("attach_dir") or DEFAULT_ATTACH)
        self.nicknames: dict[str, str] = dict(cfg.get("nicknames") or {})

        self.chats: list[dict] = []
        self.selected_id: str | None = None
        self._build()
        self.refresh()

    def _build(self) -> None:
        top = ttk.Frame(self, padding=10)
        top.pack(fill=tk.X)
        ttk.Label(top, text="聊天列表（按最近图片活动排序）").pack(side=tk.LEFT)
        ttk.Button(top, text="刷新", command=self.refresh).pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(top, text="给选中项起备注名", command=self.rename_selected).pack(
            side=tk.RIGHT
        )

        cols = ("name", "last", "months", "hd", "total", "id")
        self.tree = ttk.Treeview(
            self, columns=cols, show="headings", selectmode="browse"
        )
        self.tree.heading("name", text="备注名 / 显示名")
        self.tree.heading("last", text="最近活动")
        self.tree.heading("months", text="有图月份")
        self.tree.heading("hd", text="高清数")
        self.tree.heading("total", text="文件数")
        self.tree.heading("id", text="聊天ID")
        self.tree.column("name", width=160, anchor=tk.W)
        self.tree.column("last", width=130, anchor=tk.CENTER)
        self.tree.column("months", width=180, anchor=tk.W)
        self.tree.column("hd", width=70, anchor=tk.CENTER)
        self.tree.column("total", width=70, anchor=tk.CENTER)
        self.tree.column("id", width=160, anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        opt = ttk.LabelFrame(self, text="导出选项", padding=10)
        opt.pack(fill=tk.X, padx=10, pady=(0, 8))

        row1 = ttk.Frame(opt)
        row1.pack(fill=tk.X)
        ttk.Label(row1, text="月份：").pack(side=tk.LEFT)
        self.month_var = tk.StringVar(value="全部")
        self.month_box = ttk.Combobox(
            row1, textvariable=self.month_var, state="readonly", width=16
        )
        self.month_box["values"] = ("全部",)
        self.month_box.pack(side=tk.LEFT, padx=(0, 16))

        self.skip_thumbs = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            row1, text="跳过缩略图(_t)", variable=self.skip_thumbs
        ).pack(side=tk.LEFT, padx=(0, 12))
        self.hd_only = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            row1, text="只要高清(_h)，忽略中等画质", variable=self.hd_only
        ).pack(side=tk.LEFT)

        row2 = ttk.Frame(opt)
        row2.pack(fill=tk.X, pady=(8, 0))
        ttk.Label(row2, text="输出目录：").pack(side=tk.LEFT)
        self.out_var = tk.StringVar(value=str(DEFAULT_OUT))
        ttk.Entry(row2, textvariable=self.out_var).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8)
        )

        bottom = ttk.Frame(self, padding=10)
        bottom.pack(fill=tk.X)
        self.status = tk.StringVar(value="就绪")
        ttk.Label(bottom, textvariable=self.status).pack(side=tk.LEFT)
        self.btn = ttk.Button(bottom, text="开始解密", command=self.start_decrypt)
        self.btn.pack(side=tk.RIGHT)

        tip = (
            "提示：联系人数据库是加密的，列表默认显示聊天ID；"
            "可给常用联系人起备注名（会记住）。密钥来自 config.json。"
        )
        ttk.Label(self, text=tip, foreground="#555").pack(
            anchor=tk.W, padx=12, pady=(0, 8)
        )

    def display_name(self, chat_id: str) -> str:
        return self.nicknames.get(chat_id) or chat_id[:12] + "…"

    def refresh(self) -> None:
        self.chats = scan_chats(self.attach)
        for i in self.tree.get_children():
            self.tree.delete(i)
        for r in self.chats:
            month_preview = ",".join(r["months"][:4])
            if len(r["months"]) > 4:
                month_preview += f"…(+{len(r['months']) - 4})"
            self.tree.insert(
                "",
                tk.END,
                iid=r["id"],
                values=(
                    self.display_name(r["id"]),
                    r["last_text"],
                    month_preview,
                    r["hd_count"],
                    r["img_count"],
                    r["id"][:16] + "…",
                ),
            )
        self.status.set(f"共 {len(self.chats)} 个有图片的聊天 · {self.attach}")

    def on_select(self, _evt=None) -> None:
        sel = self.tree.selection()
        if not sel:
            self.selected_id = None
            return
        self.selected_id = sel[0]
        chat = next((c for c in self.chats if c["id"] == self.selected_id), None)
        if not chat:
            return
        values = ["全部", *chat["months"]]
        self.month_box["values"] = values
        self.month_var.set(values[1] if len(values) > 1 else "全部")
        name = self.display_name(chat["id"])
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)[:40]
        self.out_var.set(str(DEFAULT_OUT / safe))

    def rename_selected(self) -> None:
        if not self.selected_id:
            messagebox.showinfo("提示", "请先点选一个聊天")
            return
        cur = self.nicknames.get(self.selected_id, "")
        name = simpledialog.askstring(
            "备注名",
            f"为该聊天设置备注名（当前 ID：{self.selected_id[:16]}…）",
            initialvalue=cur or self.display_name(self.selected_id),
            parent=self,
        )
        if name is None:
            return
        name = name.strip()
        if not name:
            self.nicknames.pop(self.selected_id, None)
        else:
            self.nicknames[self.selected_id] = name
        cfg = load_config()
        cfg["nicknames"] = self.nicknames
        CONFIG_PATH.write_text(
            __import__("json").dumps(cfg, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        self.refresh()
        if self.selected_id in self.tree.get_children():
            self.tree.selection_set(self.selected_id)
            self.on_select()

    def start_decrypt(self) -> None:
        cfg = load_config()
        if not cfg.get("aes_key"):
            messagebox.showerror(
                "缺少密钥",
                "还没有 AES 密钥。\n请先运行「1_抓密钥.bat」，在微信里点开几张大图。",
            )
            return
        if not self.selected_id:
            messagebox.showinfo("提示", "请先选择一个聊天")
            return
        chat = next((c for c in self.chats if c["id"] == self.selected_id), None)
        if not chat:
            return

        month = self.month_var.get()
        if month == "全部":
            src = chat["path"]
        else:
            src = chat["path"] / month / "Img"
            if not src.is_dir():
                messagebox.showerror("错误", f"目录不存在：{src}")
                return

        out_dir = Path(self.out_var.get().strip() or DEFAULT_OUT)
        self.btn.configure(state=tk.DISABLED)
        self.status.set("解密中…")

        def work() -> None:
            # 临时过滤：只要高清时，先拷到临时逻辑——在 decrypt 前过滤文件列表
            code = self._decrypt_filtered(src, out_dir)
            self.after(0, lambda: self._done(code, out_dir))

        threading.Thread(target=work, daemon=True).start()

    def _decrypt_filtered(self, src: Path, out_dir: Path) -> int:
        """复用 wechat_img.cmd_decrypt，必要时先筛文件。"""
        from wechat_img import collect_v2_files, decrypt_one, resolve_keys

        aes, xor = resolve_keys(None, None)
        if not aes:
            return 1
        files = collect_v2_files(src)
        if self.skip_thumbs.get():
            files = [f for f in files if not f.name.endswith("_t.dat")]
        if self.hd_only.get():
            # 有 _h 的只留 _h；没有 _h 的保留非 _t
            hd = [f for f in files if f.name.endswith("_h.dat")]
            if hd:
                files = hd
            else:
                files = [f for f in files if not f.name.endswith("_t.dat")]
        if not files:
            return 1
        ok = 0
        for f in files:
            if decrypt_one(f, out_dir, aes, xor):
                ok += 1
        if ok:
            try:
                os.startfile(out_dir)  # noqa: S606
            except OSError:
                pass
        return 0 if ok else 2

    def _done(self, code: int, out_dir: Path) -> None:
        self.btn.configure(state=tk.NORMAL)
        if code == 0:
            self.status.set(f"完成 → {out_dir}")
            messagebox.showinfo("完成", f"解密完成\n{out_dir}")
        else:
            self.status.set("失败或没有可解密文件")
            messagebox.showerror(
                "失败",
                "没有成功解密的文件。\n若刚更新过微信，可能需要重新抓密钥。",
            )


def main() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
