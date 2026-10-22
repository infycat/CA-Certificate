#!/usr/bin/env python3
"""cert_manager.py - XCA-style certificate and key manager.

A tkinter GUI over certstore.CertStore:

  私鑰         every private key found in the project, paired to its cert
  憑證簽名請求  CSRs present on disk (and a generator for new ones)
  憑證         every certificate, with issuer / CA / serial / validity
  模板          certificate profiles used when signing
  吊銷列表      revocation records from the eMudhra inventory

Select a row in 私鑰 or 憑證 and press 簽發憑證 to mint a new certificate
under that key.  The issuer, template and validity are chosen in the dialog;
the result is written to disk and appears in the list immediately.

  python cert_manager.py
"""

from __future__ import annotations

import datetime as dt
import pathlib
import sys
import tkinter as tk
import traceback
from tkinter import filedialog, messagebox, ttk

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from certstore import CertEntry, CertStore, KeyEntry, Template, TEMPLATES, _curve_name

HERE = pathlib.Path(__file__).resolve().parent


def app_root() -> pathlib.Path:
    """Where the certificate data lives (source dir, or next to a frozen exe)."""
    if getattr(sys, "frozen", False):
        return pathlib.Path(sys.executable).resolve().parent
    return HERE


def resource_root() -> pathlib.Path:
    """Where bundled read-only resources live (icons inside the exe bundle)."""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return pathlib.Path(meipass)
    return HERE


ISSUED_DIR = app_root() / "issued"

CHECK = "\u2713"  # ✓
CROSS = "\u2717"  # ✗


def enable_dpi_awareness() -> None:
    """Make Tk and the screen agree on pixel coordinates.

    Without this Windows virtualises tkinter coordinates at 125%/150%
    scaling, so a window sized in Tk units renders larger than the bbox
    anything else measures - the right edge of the tree gets clipped.
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # system DPI aware
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def fit_geometry(win: tk.Misc, want_w: int, want_h: int) -> str:
    """Return a geometry string clamped to the usable screen."""
    try:
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
    except Exception:
        sw, sh = want_w + 80, want_h + 80
    w = min(want_w, max(720, sw - 60))
    h = min(want_h, max(480, sh - 90))
    x = max(20, (sw - w) // 2)
    y = max(20, (sh - h) // 2)
    return f"{w}x{h}+{x}+{y}"


def pick_font() -> str:
    for name in ("Microsoft JhengHei UI", "Microsoft YaHei UI", "Segoe UI", "Arial"):
        try:
            import tkinter.font as tkfont

            if name in tkfont.families():
                return name
        except Exception:
            pass
    return "TkDefaultFont"


def apply_window_icon(win: tk.Misc) -> str:
    """Set the taskbar/title-bar icon.

    A PyInstaller exe carries the icon in its PE resource, and Windows uses
    that for the taskbar - but Tk draws its own feather in the title bar
    until iconbitmap() is called.  Timing matters: calling it before the
    toplevel exists is silently ignored (WM_GETICON stays 0), so the caller
    must invoke this after update_idletasks().

    Returns a short status string for the GUI to show.
    """
    note = []
    candidates = [
        resource_root() / "assets" / "icon.ico",
        app_root() / "assets" / "icon.ico",
        HERE / "assets" / "icon.ico",
    ]
    for ico in candidates:
        if ico.exists():
            try:
                win.iconbitmap(str(ico))
                note.append(f"ico={ico.name}")
                break
            except tk.TclError as exc:
                note.append(f"ico-err={exc}")
                continue

    for png in (
        resource_root() / "assets" / "icon_256.png",
        resource_root() / "assets" / "icon.png",
        app_root() / "assets" / "icon_256.png",
        HERE / "assets" / "icon_256.png",
    ):
        if png.exists():
            try:
                img = tk.PhotoImage(file=str(png))
                win.iconphoto(True, img)
                # keep a reference or Tk garbage-collects the image
                win._icon_photo = img  # type: ignore[attr-defined]
                note.append(f"png={png.name}")
                break
            except Exception as exc:  # noqa: BLE001
                note.append(f"png-err={exc}")
                continue

    return ", ".join(note) if note else "icon not found"


def icon_handles(win: tk.Misc) -> list[int]:
    """Read back WM_GETICON so the GUI can prove the icon actually took."""
    try:
        import ctypes
        import ctypes.wintypes as wt

        user32 = ctypes.windll.user32
        hwnd = user32.GetAncestor(win.winfo_id(), 2)  # GA_ROOT
        return [user32.SendMessageW(hwnd, 0x007F, i, 0) for i in (0, 1, 2)]
    except Exception:
        return []


# --------------------------------------------------------------------------
# issue dialog
# --------------------------------------------------------------------------


class IssueDialog(tk.Toplevel):
    def __init__(
        self,
        parent: tk.Misc,
        store: CertStore,
        issuer: KeyEntry,
        default_template: Template | None = None,
    ) -> None:
        super().__init__(parent)
        self.title("簽發新憑證")
        self.store = store
        self.issuer = issuer
        self.result: tuple[x509.Certificate, object, pathlib.Path, pathlib.Path] | None = None
        self.transient(parent)
        self.resizable(True, False)

        body = ttk.Frame(self, padding=12)
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        body.columnconfigure(2, weight=0)

        row = 0

        def add_label(text: str) -> None:
            nonlocal row
            ttk.Label(body, text=text).grid(
                row=row, column=0, sticky="w", pady=3, padx=(0, 8)
            )

        # issuer info (read only)
        add_label("簽發者")
        issuer_txt = (
            f"{issuer.common_name}  ({issuer.curve}, d 對應)"
            if issuer.cert
            else issuer.common_name
        )
        ttk.Label(body, text=issuer_txt, foreground="#1a6").grid(
            row=row, column=1, sticky="w", pady=3
        )
        row += 1

        add_label("模板")
        self.template_var = tk.StringVar(
            value=(default_template or TEMPLATES[0]).name
        )
        tpl_box = ttk.Combobox(
            body,
            textvariable=self.template_var,
            values=[t.name for t in TEMPLATES],
            state="readonly",
            width=28,
        )
        tpl_box.grid(row=row, column=1, sticky="w", pady=3)
        tpl_box.bind("<<ComboboxSelected>>", lambda _e: self._on_template())
        row += 1

        add_label("模板說明")
        self.tpl_desc = ttk.Label(body, text="", foreground="#666", wraplength=380)
        self.tpl_desc.grid(row=row, column=1, sticky="w", pady=(0, 6))
        row += 1

        ttk.Separator(body, orient="horizontal").grid(
            row=row, column=0, columnspan=2, sticky="ew", pady=8
        )
        row += 1

        self.cn_var = tk.StringVar(value="new.example.test")
        self.o_var = tk.StringVar(value="")
        self.ou_var = tk.StringVar(value="")
        self.c_var = tk.StringVar(value="")
        self.san_var = tk.StringVar(value="")
        self.days_var = tk.StringVar(value="365")
        self.serial_var = tk.StringVar(value="")
        self.reuse_var = tk.BooleanVar(value=False)

        for label, var, hint in (
            ("commonName", self.cn_var, "必填"),
            ("組織 O", self.o_var, ""),
            ("單位 OU", self.ou_var, ""),
            ("國家 C", self.c_var, "兩碼,如 TW"),
            ("SAN", self.san_var, "逗號分隔,可填域名或 IP"),
            ("有效天數", self.days_var, ""),
            ("序列號", self.serial_var, "留空 = 隨機"),
        ):
            add_label(label)
            entry = ttk.Entry(body, textvariable=var, width=38)
            entry.grid(row=row, column=1, sticky="ew", pady=3)
            if hint:
                ttk.Label(body, text=hint, foreground="#999", width=24).grid(
                    row=row, column=2, sticky="w", padx=(8, 0)
                )
            row += 1

        add_label("金鑰")
        ttk.Checkbutton(
            body,
            text="沿用簽發者的金鑰 (reuse key)",
            variable=self.reuse_var,
        ).grid(row=row, column=1, sticky="w", pady=3)
        row += 1

        ttk.Separator(body, orient="horizontal").grid(
            row=row, column=0, columnspan=2, sticky="ew", pady=8
        )
        row += 1

        btns = ttk.Frame(body)
        btns.grid(row=row, column=0, columnspan=2, sticky="e")
        ttk.Button(btns, text="取消", command=self.destroy).pack(side="right", padx=4)
        ttk.Button(btns, text="簽發", command=self._issue).pack(side="right", padx=4)

        self._on_template()
        self.grab_set()
        self.cn_var.set("new.example.test")
        self.update_idletasks()
        # size the dialog to its own content, then centre it on the parent
        req_w = max(620, self.winfo_reqwidth())
        req_h = self.winfo_reqheight()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        x = px + max(0, (pw - req_w) // 2)
        y = py + max(0, (ph - req_h) // 3)
        self.geometry(f"{req_w}x{req_h}+{x}+{y}")

    def _template(self) -> Template:
        for t in TEMPLATES:
            if t.name == self.template_var.get():
                return t
        return TEMPLATES[0]

    def _on_template(self) -> None:
        t = self._template()
        bits = [f"CA={'是' if t.is_ca else '否'}"]
        if t.path_length is not None:
            bits.append(f"pathlen={t.path_length}")
        bits.append("EKU=" + (", ".join(t.eku) if t.eku else "無"))
        self.tpl_desc.config(text=f"{t.description}  ·  " + "  ·  ".join(bits))

    def _issue(self) -> None:
        cn = self.cn_var.get().strip()
        if not cn:
            messagebox.showerror("缺少 commonName", "commonName 不能空白", parent=self)
            return
        try:
            days = int(self.days_var.get().strip() or "365")
        except ValueError:
            messagebox.showerror("有效天數錯誤", "請填整數天數", parent=self)
            return
        sans = [s.strip() for s in self.san_var.get().split(",") if s.strip()]
        serial = self.serial_var.get().strip() or None
        if serial:
            try:
                int(serial.replace(":", ""), 16)
            except ValueError:
                messagebox.showerror("序列號錯誤", "請填十六進位,例如 0BADCAFE", parent=self)
                return

        try:
            cert, key = self.store.mint_leaf(
                self.issuer,
                self._template(),
                common_name=cn,
                organization=self.o_var.get().strip(),
                org_unit=self.ou_var.get().strip(),
                country=self.c_var.get().strip(),
                sans=sans,
                days=days,
                serial_hex=serial,
                reuse_key=self.reuse_var.get(),
            )
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("簽發失敗", repr(exc), parent=self)
            return

        stem = "".join(c if c.isalnum() or c in "._-" else "_" for c in cn)
        stamp = dt.datetime.now().strftime("%Y%m%d%H%M%S")
        cert_path, key_path = self.store.save_issued(
            cert, key, ISSUED_DIR, f"{stem}_{stamp}"
        )
        self.result = (cert, key, cert_path, key_path)

        messagebox.showinfo(
            "簽發完成",
            f"commonName : {cn}\n"
            f"簽發者     : {self.issuer.common_name}\n"
            f"模板       : {self._template().name}\n"
            f"序列號     : {format(cert.serial_number, 'X')}\n"
            f"有效至     : {cert.not_valid_after_utc.date()}\n\n"
            f"憑證: {cert_path}\n"
            f"私鑰: {key_path}",
            parent=self,
        )
        self.destroy()


# --------------------------------------------------------------------------
# generic text input dialog
# --------------------------------------------------------------------------


class _TextInputDialog(tk.Toplevel):
    """Simple labelled-entry dialog.  result is a tuple of values or None."""

    def __init__(self, parent: tk.Misc, title: str, fields: list[tuple[str, str]]) -> None:
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.resizable(False, False)
        self.result: tuple[str, ...] | None = None
        self._vars: list[tk.StringVar] = []

        body = ttk.Frame(self, padding=12)
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)

        for r, (label, default) in enumerate(fields):
            ttk.Label(body, text=label).grid(row=r, column=0, sticky="w", pady=3,
                                             padx=(0, 8))
            var = tk.StringVar(value=default)
            self._vars.append(var)
            ttk.Entry(body, textvariable=var, width=42).grid(
                row=r, column=1, sticky="ew", pady=3
            )

        bar = ttk.Frame(body)
        bar.grid(row=len(fields), column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(bar, text="取消", command=self.destroy).pack(side="right", padx=4)
        ttk.Button(bar, text="確定", command=self._ok).pack(side="right")

        self.grab_set()
        self.update_idletasks()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        w, h = self.winfo_reqwidth(), self.winfo_reqheight()
        self.geometry(f"{w}x{h}+{px + (pw - w)//2}+{py + (ph - h)//3}")

    def _ok(self) -> None:
        self.result = tuple(v.get().strip() for v in self._vars)
        self.destroy()


# --------------------------------------------------------------------------
# small chooser
# --------------------------------------------------------------------------


def _choose(parent: tk.Misc, title: str, prompt: str, options: list[str]) -> int | None:
    """Modal list picker.  Returns the chosen index or None."""
    dlg = tk.Toplevel(parent)
    dlg.title(title)
    dlg.transient(parent)
    dlg.resizable(False, False)
    body = ttk.Frame(dlg, padding=12)
    body.pack(fill="both", expand=True)
    ttk.Label(body, text=prompt).pack(anchor="w", pady=(0, 8))
    lb = tk.Listbox(body, height=min(12, max(4, len(options))), width=64,
                    exportselection=False, font=(pick_font(), 9))
    for o in options:
        lb.insert("end", o)
    lb.pack(fill="both", expand=True)
    if options:
        lb.selection_set(0)
    result: dict[str, int | None] = {"idx": None}

    def ok() -> None:
        sel = lb.curselection()
        result["idx"] = sel[0] if sel else None
        dlg.destroy()

    bar = ttk.Frame(body)
    bar.pack(fill="x", pady=(8, 0))
    ttk.Button(bar, text="取消", command=dlg.destroy).pack(side="right", padx=4)
    ttk.Button(bar, text="確定", command=ok).pack(side="right")
    lb.bind("<Double-1>", lambda _e: ok())
    dlg.grab_set()
    parent.wait_window(dlg)
    return result["idx"]


# --------------------------------------------------------------------------
# MCP settings dialog
# --------------------------------------------------------------------------


class _McpDialog(tk.Toplevel):
    """Start/stop the embedded MCP server and copy the client config."""

    def __init__(self, parent: "CertManagerApp", host) -> None:
        super().__init__(parent)
        self.title("MCP 伺服器")
        self.transient(parent)
        self.resizable(False, False)
        self.app = parent
        self.host = host

        body = ttk.Frame(self, padding=14)
        body.pack(fill="both", expand=True)

        ttk.Label(
            body,
            text="MCP 伺服器跑在本程式內部的背景執行緒,\n"
            "不會多開視窗,也不會出現命令列。",
            justify="left",
            foreground="#555",
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

        ttk.Label(body, text="連接埠").grid(row=1, column=0, sticky="w", pady=3)
        self.port_var = tk.StringVar(value=str(host.port))
        ttk.Entry(body, textvariable=self.port_var, width=10).grid(
            row=1, column=1, sticky="w", pady=3
        )

        ttk.Label(body, text="綁定位址").grid(row=2, column=0, sticky="w", pady=3)
        self.host_var = tk.StringVar(value=host.host)
        ttk.Combobox(
            body,
            textvariable=self.host_var,
            values=["127.0.0.1", "0.0.0.0"],
            width=16,
            state="readonly",
        ).grid(row=2, column=1, sticky="w", pady=3)
        ttk.Label(
            body,
            text="127.0.0.1 = 只有本機;0.0.0.0 = 區網可達",
            foreground="#999",
        ).grid(row=2, column=2, sticky="w", padx=(8, 0))

        self.state_var = tk.StringVar()
        ttk.Label(body, textvariable=self.state_var, foreground="#1a7f4b").grid(
            row=3, column=0, columnspan=3, sticky="w", pady=(10, 4)
        )

        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(body, textvariable=self.url_var, width=48, state="readonly")
        url_entry.grid(row=4, column=0, columnspan=3, sticky="ew", pady=3)

        self.cfg_text = tk.Text(
            body, height=7, width=56, wrap="none", font=(pick_font(), 9)
        )
        self.cfg_text.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(8, 4))

        bar = ttk.Frame(body)
        bar.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        ttk.Button(bar, text="套用並重啟", command=self._apply).pack(side="left")
        ttk.Button(bar, text="啟動", command=self._start).pack(side="left", padx=4)
        ttk.Button(bar, text="停止", command=self._stop).pack(side="left")
        ttk.Button(bar, text="複製設定", command=self._copy).pack(side="left", padx=4)
        ttk.Button(bar, text="關閉", command=self.destroy).pack(side="right")

        self._refresh()
        self.grab_set()
        self.update_idletasks()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        w, h = self.winfo_reqwidth(), self.winfo_reqheight()
        self.geometry(f"{w}x{h}+{px + (pw - w)//2}+{py + (ph - h)//3}")

    def _refresh(self) -> None:
        st = self.host.status()
        if st["running"]:
            self.state_var.set(
                f"狀態:執行中   uptime {st['uptime_s']}s   port {st['port']}"
            )
        elif st.get("error"):
            self.state_var.set(f"狀態:錯誤 — {st['error'].splitlines()[-1]}")
        else:
            self.state_var.set("狀態:未啟動")
        self.url_var.set(st["url"])

        import json

        import mcp_server

        cfg = json.dumps(mcp_server.client_config(self.host), indent=2)
        self.cfg_text.delete("1.0", "end")
        self.cfg_text.insert("1.0", cfg)

    def _parse(self) -> tuple[int, str] | None:
        try:
            port = int(self.port_var.get().strip())
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("連接埠錯誤", "請填 1–65535", parent=self)
            return None
        return port, self.host_var.get().strip()

    def _apply(self) -> None:
        parsed = self._parse()
        if parsed is None:
            return
        port, bind = parsed
        ok = self.host.restart(port=port, host=bind)
        self._refresh()
        self.app._update_mcp_status()
        if not ok:
            messagebox.showerror(
                "啟動失敗",
                f"{self.host.status().get('error') or '未知錯誤'}\n\n"
                "可能是連接埠被占用。",
                parent=self,
            )

    def _start(self) -> None:
        parsed = self._parse()
        if parsed is None:
            return
        port, bind = parsed
        if (port, bind) != (self.host.port, self.host.host):
            ok = self.host.restart(port=port, host=bind)
        else:
            ok = self.host.start()
        self._refresh()
        self.app._update_mcp_status()
        if not ok:
            messagebox.showerror(
                "啟動失敗", self.host.status().get("error") or "未知錯誤", parent=self
            )

    def _stop(self) -> None:
        self.host.stop()
        self._refresh()
        self.app._update_mcp_status()

    def _copy(self) -> None:
        cfg = self.cfg_text.get("1.0", "end").strip()
        self.clipboard_clear()
        self.clipboard_append(cfg)
        messagebox.showinfo("已複製", "設定已放進剪貼簿。", parent=self)


# --------------------------------------------------------------------------
# main window
# --------------------------------------------------------------------------


class CertManagerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("X Certificate and Key management  —  nixgc cert manager")
        self.geometry(fit_geometry(self, 1240, 720))
        self.minsize(900, 520)

        self.store = CertStore()
        self.store.load_all()

        self.font_name = pick_font()
        self._apply_style()

        self.mcp_host = None  # started from main() or the 其他工具 menu
        self._build_menu()
        self._build_layout()
        self.refresh_all()

        # The toplevel must exist before iconbitmap has any effect, otherwise
        # WM_GETICON stays 0 and Windows keeps drawing Tk's feather.
        self.update_idletasks()
        self.icon_status = apply_window_icon(self)
        self.icon_handles = icon_handles(self)

    # -- chrome ----------------------------------------------------------

    def _apply_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            try:
                style.theme_use("clam")
            except tk.TclError:
                pass
        style.configure(".", font=(self.font_name, 9))
        style.configure("Treeview", rowheight=22, font=(self.font_name, 9))
        style.configure("Treeview.Heading", font=(self.font_name, 9, "bold"))
        style.configure("TNotebook.Tab", padding=(12, 5))

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)

        m_file = tk.Menu(menubar, tearoff=0)
        m_file.add_command(label="重新載入全部", command=self.refresh_all)
        m_file.add_command(label="匯入 PEM 憑證…", command=self._import_pem)
        m_file.add_separator()
        m_file.add_command(label="結束", command=self.destroy)
        menubar.add_cascade(label="文件", menu=m_file)

        m_import = tk.Menu(menubar, tearoff=0)
        m_import.add_command(label="匯入憑證檔…", command=self._import_pem)
        m_import.add_command(label="匯入私鑰…", command=self._import_key)
        menubar.add_cascade(label="導入", menu=m_import)

        m_token = tk.Menu(menubar, tearoff=0)
        m_token.add_command(label="列出已載入金鑰", command=self._list_keys)
        menubar.add_cascade(label="令牌", menu=m_token)

        m_tools = tk.Menu(menubar, tearoff=0)
        m_tools.add_command(label="簽發憑證…", command=self._issue_from_selection)
        m_tools.add_command(label="驗證選取憑證鏈", command=self._verify_selection)
        m_tools.add_separator()
        m_tools.add_command(label="匯出選取 PEM…", command=self._export_selection)
        m_tools.add_separator()
        m_tools.add_command(label="MCP 伺服器設定…", command=self._mcp_dialog)
        m_tools.add_command(label="啟動 MCP 伺服器", command=self._mcp_start)
        m_tools.add_command(label="停止 MCP 伺服器", command=self._mcp_stop)
        m_tools.add_command(label="複製 MCP 連線設定", command=self._mcp_copy_config)
        menubar.add_cascade(label="其他工具", menu=m_tools)

        m_help = tk.Menu(menubar, tearoff=0)
        m_help.add_command(label="關於", command=self._about)
        menubar.add_cascade(label="幫助", menu=m_help)

        self.config(menu=menubar)

    def _build_layout(self) -> None:
        outer = ttk.Frame(self, padding=(8, 6))
        outer.pack(fill="both", expand=True)

        self.nb = ttk.Notebook(outer)
        self.nb.pack(fill="both", expand=True)
        self.tab_keys = ttk.Frame(self.nb, padding=4)
        self.tab_csr = ttk.Frame(self.nb, padding=4)
        self.tab_certs = ttk.Frame(self.nb, padding=4)
        self.tab_tpl = ttk.Frame(self.nb, padding=4)
        self.tab_crl = ttk.Frame(self.nb, padding=4)

        self.nb.add(self.tab_keys, text="私鑰")
        self.nb.add(self.tab_csr, text="憑證簽名請求")
        self.nb.add(self.tab_certs, text="憑證")
        self.nb.add(self.tab_tpl, text="模板")
        self.nb.add(self.tab_crl, text="吊銷列表")

        self._build_keys_tab()
        self._build_csr_tab()
        self._build_certs_tab()
        self._build_templates_tab()
        self._build_crl_tab()
        self._build_detail(outer)

        bar = ttk.Frame(outer)
        bar.pack(fill="x", pady=(6, 0))
        ttk.Button(bar, text="簽發憑證…", command=self._issue_from_selection).pack(
            side="left"
        )
        ttk.Button(bar, text="驗證鏈", command=self._verify_selection).pack(
            side="left", padx=6
        )
        ttk.Button(bar, text="匯出 PEM…", command=self._export_selection).pack(
            side="left"
        )
        ttk.Button(bar, text="重新載入", command=self.refresh_all).pack(side="left", padx=6)
        self.mcp_label = ttk.Label(bar, text="  MCP 未啟動 ", foreground="#888")
        self.mcp_label.pack(side="left", padx=(14, 0))
        self.status = ttk.Label(bar, text="", foreground="#555")
        self.status.pack(side="right")

    # -- private keys tab ------------------------------------------------

    def _build_keys_tab(self) -> None:
        cols = ("internal", "cn", "keyname", "ca", "serial", "expires")
        heads = ("內部名稱", "commonName", "密鑰名稱", "CA", "序列號", "失效時間")
        widths = (250, 250, 220, 50, 260, 110)

        self.tree_keys = ttk.Treeview(
            self.tab_keys, columns=cols, show="headings", selectmode="browse"
        )
        for c, h, w in zip(cols, heads, widths):
            self.tree_keys.heading(c, text=h, command=lambda cc=c: self._sort("keys", cc))
            anchor = "center" if c in ("ca", "expires") else "w"
            self.tree_keys.column(c, width=w, anchor=anchor, stretch=(c in ("internal", "cn")))
        self.tree_keys.tag_configure("revoked", foreground="#a00")
        self.tree_keys.tag_configure("nokey", foreground="#888")
        self.tree_keys.tag_configure("noca", foreground="#333")

        sb = ttk.Scrollbar(self.tab_keys, orient="vertical", command=self.tree_keys.yview)
        self.tree_keys.configure(yscrollcommand=sb.set)
        self.tree_keys.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self.tree_keys.bind("<<TreeviewSelect>>", self._on_key_select)
        self.tree_keys.bind("<Double-1>", lambda _e: self._issue_from_selection())
        self.tree_keys.bind("<Button-3>", self._key_context)

        self.key_menu = tk.Menu(self, tearoff=0)
        self.key_menu.add_command(label="簽發憑證…", command=self._issue_from_selection)
        self.key_menu.add_command(label="匯出私鑰…", command=self._export_selection)
        self.key_menu.add_command(label="驗證對應憑證鏈", command=self._verify_selection)

    # -- csr tab ---------------------------------------------------------

    def _build_csr_tab(self) -> None:
        top = ttk.Frame(self.tab_csr)
        top.pack(fill="x", pady=(0, 4))
        ttk.Button(top, text="產生 CSR…", command=self._new_csr).pack(side="left")
        ttk.Button(top, text="以 CSR 簽發憑證…", command=self._sign_csr).pack(
            side="left", padx=6
        )
        ttk.Label(
            top,
            text="CSR 只帶公鑰;簽發時保留 CSR 的主體與 SAN。",
            foreground="#666",
        ).pack(side="left", padx=8)

        cols = ("name", "cn", "valid", "path")
        self.tree_csr = ttk.Treeview(
            self.tab_csr, columns=cols, show="headings", selectmode="browse"
        )
        for c, h, w in (
            ("name", "內部名稱", 220),
            ("cn", "commonName", 240),
            ("valid", "簽章", 70),
            ("path", "路徑", 480),
        ):
            self.tree_csr.heading(c, text=h)
            self.tree_csr.column(c, width=w, anchor="center" if c == "valid" else "w")
        sb = ttk.Scrollbar(self.tab_csr, orient="vertical", command=self.tree_csr.yview)
        self.tree_csr.configure(yscrollcommand=sb.set)
        self.tree_csr.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree_csr.bind("<<TreeviewSelect>>", self._on_csr_select)
        self.tree_csr.bind("<Double-1>", lambda _e: self._sign_csr())

    def _csr_entries(self) -> list[tuple[pathlib.Path, x509.CertificateSigningRequest | None]]:
        out: list[tuple[pathlib.Path, x509.CertificateSigningRequest | None]] = []
        for d in (app_root() / "csr", app_root() / "pki", ISSUED_DIR):
            if not d.is_dir():
                continue
            for f in sorted(d.glob("*.csr*")):
                try:
                    out.append((f, x509.load_pem_x509_csr(f.read_bytes())))
                except Exception:
                    out.append((f, None))
        return out

    # -- certificates tab ------------------------------------------------

    def _build_certs_tab(self) -> None:
        cols = ("internal", "cn", "issuer", "ca", "serial", "expires", "state")
        heads = ("內部名稱", "commonName", "簽發者", "CA", "序列號", "失效時間", "狀態")
        widths = (230, 220, 210, 46, 240, 100, 80)

        self.tree_certs = ttk.Treeview(
            self.tab_certs, columns=cols, show="headings", selectmode="browse"
        )
        for c, h, w in zip(cols, heads, widths):
            self.tree_certs.heading(c, text=h, command=lambda cc=c: self._sort("certs", cc))
            anchor = "center" if c in ("ca", "expires", "state") else "w"
            self.tree_certs.column(c, width=w, anchor=anchor, stretch=(c in ("internal", "cn")))
        self.tree_certs.tag_configure("revoked", foreground="#a00")
        self.tree_certs.tag_configure("expired", foreground="#a60")

        sb = ttk.Scrollbar(self.tab_certs, orient="vertical", command=self.tree_certs.yview)
        self.tree_certs.configure(yscrollcommand=sb.set)
        self.tree_certs.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self.tree_certs.bind("<<TreeviewSelect>>", self._on_cert_select)
        self.tree_certs.bind("<Double-1>", lambda _e: self._issue_from_selection())
        self.tree_certs.bind("<Button-3>", self._cert_context)

        self.cert_menu = tk.Menu(self, tearoff=0)
        self.cert_menu.add_command(label="以此為簽發者簽發…", command=self._issue_from_selection)
        self.cert_menu.add_command(label="驗證鏈", command=self._verify_selection)
        self.cert_menu.add_command(label="匯出 PEM…", command=self._export_selection)

    # -- templates tab ---------------------------------------------------

    def _build_templates_tab(self) -> None:
        top = ttk.Frame(self.tab_tpl)
        top.pack(fill="x", pady=(0, 4))
        ttk.Label(
            top,
            text="選一個模板後按下方「簽發憑證…」;或先選金鑰再簽發。",
            foreground="#666",
        ).pack(side="left")

        cols = ("name", "ca", "pathlen", "eku", "desc")
        heads = ("模板名稱", "CA", "pathlen", "EKU", "說明")
        widths = (180, 50, 70, 240, 420)
        self.tree_tpl = ttk.Treeview(
            self.tab_tpl, columns=cols, show="headings", selectmode="browse"
        )
        for c, h, w in zip(cols, heads, widths):
            self.tree_tpl.heading(c, text=h)
            anchor = "center" if c in ("ca", "pathlen") else "w"
            self.tree_tpl.column(c, width=w, anchor=anchor)
        sb = ttk.Scrollbar(self.tab_tpl, orient="vertical", command=self.tree_tpl.yview)
        self.tree_tpl.configure(yscrollcommand=sb.set)
        self.tree_tpl.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree_tpl.bind("<<TreeviewSelect>>", self._on_template_select)

    # -- revocation tab --------------------------------------------------

    def _build_crl_tab(self) -> None:
        cols = ("name", "serial", "reason", "date", "crl")
        heads = ("憑證", "序列號", "原因", "撤銷時間", "CRL 來源")
        widths = (250, 250, 120, 160, 320)
        self.tree_crl = ttk.Treeview(
            self.tab_crl, columns=cols, show="headings", selectmode="browse"
        )
        for c, h, w in zip(cols, heads, widths):
            self.tree_crl.heading(c, text=h)
            self.tree_crl.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(self.tab_crl, orient="vertical", command=self.tree_crl.yview)
        self.tree_crl.configure(yscrollcommand=sb.set)
        self.tree_crl.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree_crl.tag_configure("revoked", foreground="#a00")

    # -- detail pane -----------------------------------------------------

    def _build_detail(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="詳細資料", padding=6)
        frame.pack(fill="both", expand=False, pady=(6, 0))

        self.detail = tk.Text(
            frame,
            height=10,
            wrap="none",
            font=(self.font_name, 9),
            background="#fbfbfb",
            relief="flat",
            borderwidth=0,
        )
        ysb = ttk.Scrollbar(frame, orient="vertical", command=self.detail.yview)
        xsb = ttk.Scrollbar(frame, orient="horizontal", command=self.detail.xview)
        self.detail.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.detail.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.detail.configure(state="disabled")

    # -- refresh ---------------------------------------------------------

    def refresh_all(self) -> None:
        self.store = CertStore()
        self.store.load_all()
        self._fill_keys()
        self._fill_certs()
        self._fill_csrs()
        self._fill_templates()
        self._fill_crl()
        self.status.config(
            text=f"憑證 {len(self.store.certs)} · 私鑰 {len(self.store.keys)} "
            f"· CA 金鑰 {len(self.store.ca_keys)} · 吊銷 {len(self.store.revocations)}"
        )
        self._clear_detail()

    def _fill_keys(self) -> None:
        self.tree_keys.delete(*self.tree_keys.get_children())
        for k in self.store.keys:
            c = k.cert
            tags: tuple[str, ...] = ()
            if c is not None and c.revoked:
                tags = ("revoked",)
            elif c is None:
                tags = ("nokey",)
            elif not k.is_ca:
                tags = ("noca",)
            self.tree_keys.insert(
                "",
                "end",
                iid=k.path,
                values=(
                    k.internal_name or k.key_name,
                    k.common_name,
                    f"{CHECK} {k.key_name}",
                    CHECK if k.is_ca else "0",
                    k.serial_hex or "",
                    k.not_after.date().isoformat() if k.not_after else "",
                ),
                tags=tags,
            )

    def _fill_certs(self) -> None:
        self.tree_certs.delete(*self.tree_certs.get_children())
        for c in self.store.certs:
            tags: tuple[str, ...] = ()
            state = "有效"
            if c.revoked:
                state = "已吊銷"
                tags = ("revoked",)
            elif c.expired:
                state = "已過期"
                tags = ("expired",)
            self.tree_certs.insert(
                "",
                "end",
                iid=c.sha256,
                values=(
                    c.internal_name or c.common_name,
                    c.common_name,
                    c.issuer_cn,
                    CHECK if c.is_ca else "0",
                    c.serial_hex,
                    c.not_after.date().isoformat(),
                    state,
                ),
                tags=tags,
            )

    def _fill_csrs(self) -> None:
        self.tree_csr.delete(*self.tree_csr.get_children())
        for path, csr in self._csr_entries():
            if csr is None:
                self.tree_csr.insert(
                    "", "end", iid=str(path), values=(path.stem, "(無法解析)", "", str(path))
                )
                continue
            cn = ""
            for a in csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                cn = str(a.value)
            self.tree_csr.insert(
                "",
                "end",
                iid=str(path),
                values=(
                    path.stem,
                    cn,
                    CHECK if csr.is_signature_valid else CROSS,
                    str(path),
                ),
            )

    def _on_csr_select(self, _event=None) -> None:
        sel = self.tree_csr.selection()
        if not sel:
            return
        path = pathlib.Path(sel[0])
        try:
            csr = x509.load_pem_x509_csr(path.read_bytes())
        except Exception:
            self._set_detail(f"{path}\n\n無法解析為 CSR。")
            return
        lines = [
            f"CSR 檔案   : {path}",
            f"主體       : {csr.subject.rfc4514_string()}",
            f"簽章有效   : {csr.is_signature_valid}",
            f"簽章演算法 : {csr.signature_algorithm_oid.dotted_string}",
            f"金鑰       : {_curve_name(csr.public_key())}",
        ]
        try:
            san = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            names = [str(n.value) for n in san]
            lines.append(f"SAN        : {', '.join(names) if names else '無'}")
        except x509.ExtensionNotFound:
            lines.append("SAN        : 無")
        lines += ["", "按「以 CSR 簽發憑證…」用它簽一張。"]
        self._set_detail("\n".join(lines))

    def _new_csr(self) -> None:
        keys = [k for k in self.store.keys if k.cert is not None]
        if not keys:
            messagebox.showinfo("沒有金鑰", "找不到可用的金鑰。", parent=self)
            return
        idx = _choose(
            self,
            "選擇金鑰",
            "用哪一把金鑰產生 CSR?",
            [f"{k.common_name}  ({k.curve})" for k in keys],
        )
        if idx is None:
            return
        key = keys[idx]
        dlg = _TextInputDialog(
            self,
            "產生 CSR",
            [
                ("commonName", "new.example.test"),
                ("組織 O", ""),
                ("單位 OU", ""),
                ("國家 C", ""),
                ("SAN", ""),
            ],
        )
        if dlg.result is None:
            return
        cn, org, ou, c, san = dlg.result
        try:
            csr = self.store.create_csr(
                key,
                common_name=cn,
                organization=org,
                org_unit=ou,
                country=c,
                sans=[s.strip() for s in san.split(",") if s.strip()],
            )
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("產生失敗", repr(exc), parent=self)
            return
        out = app_root() / "csr"
        out.mkdir(exist_ok=True)
        stem = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in cn)
        path = out / f"{stem}.csr.pem"
        path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
        self._fill_csrs()
        self.status.config(text=f"已產生 CSR {path.name}")

    def _sign_csr(self) -> None:
        sel = self.tree_csr.selection()
        if not sel:
            messagebox.showinfo("先選一個 CSR", "請在清單裡選一筆。", parent=self)
            return
        path = pathlib.Path(sel[0])
        try:
            csr = x509.load_pem_x509_csr(path.read_bytes())
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("讀取失敗", repr(exc), parent=self)
            return
        ca_keys = [k for k in self.store.ca_keys if k.cert is not None]
        if not ca_keys:
            messagebox.showinfo("沒有 CA", "找不到帶憑證的 CA 金鑰。", parent=self)
            return
        idx = _choose(
            self,
            "選擇簽發者",
            f"用哪個 CA 簽 {csr.subject.rfc4514_string()}?",
            [f"{k.common_name}  ({k.curve})" for k in ca_keys],
        )
        if idx is None:
            return
        issuer = ca_keys[idx]
        tpl = TEMPLATES[0]
        sel_tpl = self.tree_tpl.selection()
        if sel_tpl:
            tpl = TEMPLATES[int(sel_tpl[0])]
        try:
            cert = self.store.sign_csr(issuer, csr, tpl, days=365)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("簽發失敗", repr(exc), parent=self)
            return
        stem = "".join(
            ch if ch.isalnum() or ch in "._-" else "_" for ch in path.stem
        )
        stamp = dt.datetime.now().strftime("%Y%m%d%H%M%S")
        cp = ISSUED_DIR / f"{stem}_{stamp}.crt.pem"
        ISSUED_DIR.mkdir(exist_ok=True)
        cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.store._add_cert(cert, str(cp), "CSR 簽發")
        self._fill_certs()
        messagebox.showinfo(
            "已簽發",
            f"{cert.subject.rfc4514_string()}\n"
            f"簽發者 {issuer.common_name}\n"
            f"序號 {format(cert.serial_number, 'X')}\n\n{cp}",
            parent=self,
        )

    def _fill_templates(self) -> None:
        self.tree_tpl.delete(*self.tree_tpl.get_children())
        for i, t in enumerate(TEMPLATES):
            self.tree_tpl.insert(
                "",
                "end",
                iid=str(i),
                values=(
                    t.name,
                    "是" if t.is_ca else "否",
                    "" if t.path_length is None else t.path_length,
                    ", ".join(t.eku) if t.eku else "無",
                    t.description,
                ),
            )

    def _fill_crl(self) -> None:
        self.tree_crl.delete(*self.tree_crl.get_children())
        for r in self.store.revocations:
            self.tree_crl.insert(
                "",
                "end",
                values=(
                    r.get("name", ""),
                    r.get("serial", ""),
                    r.get("reason", ""),
                    r.get("date", ""),
                    r.get("crl", ""),
                ),
                tags=("revoked",),
            )

    # -- selection -------------------------------------------------------

    def _selected_key(self) -> KeyEntry | None:
        tab = self.nb.index(self.nb.select())
        if tab == 0:
            sel = self.tree_keys.selection()
            return self.store.key_by_path(sel[0]) if sel else None
        if tab == 2:
            sel = self.tree_certs.selection()
            if not sel:
                return None
            c = self.store.cert_by_sha(sel[0])
            if c is None or not c.key_path:
                return None
            return self.store.key_by_path(c.key_path)
        return None

    def _selected_cert(self) -> CertEntry | None:
        tab = self.nb.index(self.nb.select())
        if tab == 2:
            sel = self.tree_certs.selection()
            return self.store.cert_by_sha(sel[0]) if sel else None
        if tab == 0:
            k = self._selected_key()
            return k.cert if k else None
        return None

    def _on_key_select(self, _event=None) -> None:
        k = self._selected_key()
        if k is None:
            return
        self._show_key(k)

    def _on_cert_select(self, _event=None) -> None:
        c = self._selected_cert()
        if c is None:
            return
        self._show_cert(c)

    def _on_template_select(self, _event=None) -> None:
        sel = self.tree_tpl.selection()
        if not sel:
            return
        t = TEMPLATES[int(sel[0])]
        lines = [
            f"模板      : {t.name}",
            f"說明      : {t.description}",
            f"CA        : {'是' if t.is_ca else '否'}",
            f"pathlen   : {t.path_length if t.path_length is not None else '—'}",
            f"EKU       : {', '.join(t.eku) if t.eku else '無'}",
            f"金鑰用途  : digitalSignature={t.key_usage_sign} "
            f"keyEncipherment={t.key_usage_encipher}",
            "",
            "用此模板簽發:選一把金鑰 → 「簽發憑證…」→ 在模板下拉選這一項。",
        ]
        self._set_detail("\n".join(lines))

    def _key_context(self, event) -> None:
        row = self.tree_keys.identify_row(event.y)
        if row:
            self.tree_keys.selection_set(row)
            self.key_menu.tk_popup(event.x_root, event.y_root)

    def _cert_context(self, event) -> None:
        row = self.tree_certs.identify_row(event.y)
        if row:
            self.tree_certs.selection_set(row)
            self.cert_menu.tk_popup(event.x_root, event.y_root)

    # -- detail rendering ------------------------------------------------

    def _set_detail(self, text: str) -> None:
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    def _clear_detail(self) -> None:
        self._set_detail("選取左側任一列以檢視詳細資料。")

    def _show_key(self, k: KeyEntry) -> None:
        lines = [
            f"私鑰檔案   : {k.path}",
            f"內部名稱   : {k.internal_name}",
            f"曲線 / 位元: {k.curve}",
            f"公鑰指紋   : {k.fingerprint}",
            f"來源       : {k.source}",
        ]
        if k.cert:
            c = k.cert
            lines += [
                "",
                f"對應憑證   : {c.common_name}",
                f"主體       : {c.cert.subject.rfc4514_string()}",
                f"簽發者     : {c.cert.issuer.rfc4514_string()}",
                f"序列號     : {c.serial_hex}",
                f"有效期間   : {c.not_before.date()} → {c.not_after.date()}"
                f"  ({c.days_left} 天)",
                f"CA         : {'是' if c.is_ca else '否'}"
                + (f"  pathlen={c.path_length}" if c.path_length is not None else ""),
                f"EKU        : {', '.join(c.eku) if c.eku else '無'}",
                f"SHA-256    : {c.sha256}",
            ]
            if c.revoked:
                lines.append(
                    f"吊銷       : {c.revoked.get('status')} "
                    f"{c.revoked.get('date')} ({c.revoked.get('reason')})"
                )
        else:
            lines.append("")
            lines.append("此私鑰沒有對應的憑證 — 可以用它簽發新的憑證。")
        self._set_detail("\n".join(lines))

    def _show_cert(self, c: CertEntry) -> None:
        lines = [
            f"內部名稱   : {c.internal_name}",
            f"主體       : {c.cert.subject.rfc4514_string()}",
            f"簽發者     : {c.cert.issuer.rfc4514_string()}",
            f"序列號     : {c.serial_hex}",
            f"有效期間   : {c.not_before.date()} → {c.not_after.date()}"
            f"  ({c.days_left} 天)",
            f"CA         : {'是' if c.is_ca else '否'}"
            + (f"  pathlen={c.path_length}" if c.path_length is not None else ""),
            f"EKU        : {', '.join(c.eku) if c.eku else '無'}",
            f"金鑰       : {c.curve}",
            f"SPKI 指紋  : {c.spki}",
            f"SHA-256    : {c.sha256}",
            f"私鑰       : {c.key_path or '(沒有)'}",
            f"來源       : {c.source}",
        ]
        try:
            san = c.cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            names = [str(n.value) for n in san]
            lines.append(f"SAN        : {', '.join(names) if names else '無'}")
        except x509.ExtensionNotFound:
            lines.append("SAN        : 無")
        if c.revoked:
            lines.append(
                f"吊銷       : {c.revoked.get('status')} "
                f"{c.revoked.get('date')} ({c.revoked.get('reason')})"
            )
        lines += ["", "— 簽章鏈 —"]
        for subject, ok, note in self.store.verify_chain(c):
            lines.append(f"  {'✓' if ok else '✗'} {subject}  —  {note}")
        self._set_detail("\n".join(lines))

    # -- actions ---------------------------------------------------------

    def _issue_from_selection(self) -> None:
        key = self._selected_key()
        tpl = None
        sel_tpl = self.tree_tpl.selection()
        if sel_tpl:
            tpl = TEMPLATES[int(sel_tpl[0])]
        if key is None:
            # no key selected: offer the first CA key that has a certificate
            ca_keys = [k for k in self.store.ca_keys if k.cert is not None]
            if not ca_keys:
                messagebox.showinfo(
                    "沒有可用的簽發者",
                    "專案裡找不到帶憑證的 CA 金鑰。",
                    parent=self,
                )
                return
            names = [f"{k.common_name}  ({k.curve})" for k in ca_keys]
            choice = _choose(self, "選擇簽發者", "要用哪一把金鑰簽發?", names)
            if choice is None:
                return
            key = ca_keys[choice]
        if key.cert is None:
            messagebox.showinfo(
                "這把金鑰沒有憑證",
                "簽發需要一個憑證當簽發者。請選有對應憑證的金鑰。",
                parent=self,
            )
            return
        dlg = IssueDialog(self, self.store, key, tpl)
        self.wait_window(dlg)
        if dlg.result:
            self._fill_keys()
            self._fill_certs()
            self.status.config(
                text=f"已簽發 {dlg.result[0].subject.rfc4514_string()}"
            )

    def _verify_selection(self) -> None:
        c = self._selected_cert()
        if c is None:
            messagebox.showinfo("先選一張憑證", "請選一列憑證再驗證。", parent=self)
            return
        steps = self.store.verify_chain(c)
        text = "\n".join(f"{'✓' if ok else '✗'} {s}  —  {n}" for s, ok, n in steps)
        ok = all(x[1] for x in steps)
        (messagebox.showinfo if ok else messagebox.showwarning)(
            "鏈驗證結果", text, parent=self
        )

    def _export_selection(self) -> None:
        c = self._selected_cert()
        if c is None:
            messagebox.showinfo("先選一張憑證", "請選一列憑證再匯出。", parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".pem",
            initialfile=f"{c.common_name}.pem",
            filetypes=[("PEM", "*.pem"), ("所有檔案", "*.*")],
        )
        if not path:
            return
        pathlib.Path(path).write_bytes(c.pem)
        self.status.config(text=f"已匯出 {path}")

    def _import_pem(self) -> None:
        paths = filedialog.askopenfilenames(
            parent=self,
            filetypes=[("PEM/DER", "*.pem *.crt *.cer *.der"), ("所有檔案", "*.*")],
        )
        if not paths:
            return
        added = 0
        for p in paths:
            blob = pathlib.Path(p).read_bytes()
            try:
                if b"-----BEGIN" in blob:
                    certs = x509.load_pem_x509_certificates(blob)
                else:
                    certs = [x509.load_der_x509_certificate(blob)]
            except Exception as exc:  # noqa: BLE001
                messagebox.showerror("匯入失敗", f"{p}\n{exc}", parent=self)
                continue
            for cert in certs:
                if self.store._add_cert(cert, p, "匯入"):
                    added += 1
        self._fill_certs()
        self.status.config(text=f"匯入 {added} 張憑證")

    def _import_key(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            filetypes=[("PEM", "*.pem *.key"), ("所有檔案", "*.*")],
        )
        if not path:
            return
        k = self.store._load_key(pathlib.Path(path), "匯入")
        if k is None:
            messagebox.showerror("匯入失敗", "不是可解析的私鑰", parent=self)
            return
        self.store._pair_keys()
        self._fill_keys()
        self.status.config(text=f"匯入私鑰 {k.key_name}")

    def _list_keys(self) -> None:
        lines = [
            f"{k.key_name}  ({k.curve})  ->  {k.common_name}"
            for k in self.store.keys
        ]
        messagebox.showinfo("已載入金鑰", "\n".join(lines) or "(無)", parent=self)

    def _about(self) -> None:
        mcp_state = "未啟動"
        if self.mcp_host is not None and self.mcp_host.running():
            mcp_state = self.mcp_host.url
        messagebox.showinfo(
            "關於",
            "nixgc cert manager 1.1.0\n\n"
            "XCA 風格的憑證 / 私鑰管理器。\n"
            "MCP 伺服器內建,同一支程式、背景執行緒。\n\n"
            f"資料目錄 : {app_root()}\n"
            f"圖示     : {self.icon_status}\n"
            f"MCP      : {mcp_state}",
            parent=self,
        )

    # -- embedded MCP server ---------------------------------------------

    def _ensure_mcp(self):
        """Create the host on first use, wiring it to this app's store."""
        if self.mcp_host is not None:
            return self.mcp_host
        import mcp_server

        # share one store: what the GUI has loaded is what the MCP serves
        mcp_server._store = self.store
        self.mcp_host = mcp_server.MCPHost(port=8765)
        return self.mcp_host

    def _mcp_start(self) -> None:
        host = self._ensure_mcp()
        if host.running():
            messagebox.showinfo(
                "MCP 已在執行",
                f"端點:\n{host.url}\n\n"
                "在「其他工具 → 複製 MCP 連線設定」取得給客戶端的 JSON。",
                parent=self,
            )
            return
        ok = host.start()
        st = host.status()
        if ok:
            self._update_mcp_status()
            messagebox.showinfo(
                "MCP 已啟動",
                f"端點:\n{st['url']}\n\n"
                "背景執行緒,不會有額外視窗或命令列。\n"
                "關閉本程式時一併停止。",
                parent=self,
            )
        else:
            messagebox.showerror(
                "MCP 啟動失敗",
                f"{st.get('error') or '未知錯誤'}\n\n"
                "常見原因:連接埠 8765 已被占用。\n"
                "用「MCP 伺服器設定…」換一個埠。",
                parent=self,
            )

    def _mcp_stop(self) -> None:
        if self.mcp_host is None or not self.mcp_host.running():
            messagebox.showinfo("MCP 未執行", "目前沒有在跑。", parent=self)
            return
        self.mcp_host.stop()
        self._update_mcp_status()
        messagebox.showinfo("MCP 已停止", "背景執行緒已結束。", parent=self)

    def _mcp_copy_config(self) -> None:
        host = self._ensure_mcp()
        import json

        import mcp_server

        cfg = json.dumps(mcp_server.client_config(host), indent=2)
        self.clipboard_clear()
        self.clipboard_append(cfg)
        messagebox.showinfo(
            "已複製連線設定",
            "已放進剪貼簿:\n\n"
            f"{cfg}\n\n"
            "貼進 Claude Desktop 的 claude_desktop_config.json,\n"
            "或任何支援 HTTP MCP 的客戶端。",
            parent=self,
        )

    def _mcp_dialog(self) -> None:
        host = self._ensure_mcp()
        dlg = _McpDialog(self, host)
        self.wait_window(dlg)
        self._update_mcp_status()

    def _update_mcp_status(self) -> None:
        if not hasattr(self, "mcp_label"):
            return
        host = self.mcp_host
        if host is not None and host.running():
            self.mcp_label.config(
                text=f"  MCP {host.url} ", foreground="#1a7f4b"
            )
        else:
            self.mcp_label.config(text="  MCP 未啟動 ", foreground="#888")

    # -- sorting ---------------------------------------------------------

    def _sort(self, which: str, col: str) -> None:
        tree = self.tree_keys if which == "keys" else self.tree_certs
        rows = [(tree.set(iid, col), iid) for iid in tree.get_children("")]
        reverse = getattr(self, f"_sort_rev_{which}_{col}", False)
        rows.sort(key=lambda r: r[0].lower(), reverse=reverse)
        for idx, (_v, iid) in enumerate(rows):
            tree.move(iid, "", idx)
        setattr(self, f"_sort_rev_{which}_{col}", not reverse)


def _install_crash_log() -> pathlib.Path:
    """Windowed builds have no console, so a startup failure would be silent.

    Every unhandled exception is appended to crash.log next to the exe (or
    next to this file when running from source), plus a Tk error dialog when
    one can still be shown.
    """
    log_path = app_root() / "crash.log"

    def handler(exc_type, exc_value, exc_tb):
        import traceback

        text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        try:
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(f"\n=== {dt.datetime.now().isoformat()} ===\n")
                fh.write(f"frozen={getattr(sys, 'frozen', False)}\n")
                fh.write(f"app_root={app_root()}\n")
                fh.write(text)
        except Exception:
            pass
        try:
            import tkinter.messagebox as mb

            mb.showerror(
                "啟動失敗",
                f"{exc_type.__name__}: {exc_value}\n\n"
                f"詳細堆疊已寫入:\n{log_path}",
            )
        except Exception:
            pass
        return None

    sys.excepthook = handler
    return log_path


def _ensure_std_streams() -> None:
    """A --windowed PyInstaller build has sys.stdout/sys.stderr set to None.

    Any library that writes to them (uvicorn's log config calls .isatty(),
    traceback printers, warnings) explodes with AttributeError.  Give them a
    real file object that goes nowhere instead of leaving them None.
    """
    import io
    import os

    if sys.stdout is not None and sys.stderr is not None:
        return
    sink = open(os.devnull, "w", encoding="utf-8")
    if sys.stdout is None:
        sys.stdout = sink
    if sys.stderr is None:
        sys.stderr = sink
    # keep a reference so the file is not collected
    globals()["_std_sink"] = sink


def main() -> int:
    _ensure_std_streams()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    _install_crash_log()
    app = None
    try:
        enable_dpi_awareness()
        app = CertManagerApp()
        # the MCP server is part of this process, started with the window
        try:
            host = app._ensure_mcp()
            if host.start():
                app._update_mcp_status()
            else:
                err = host.status().get("error")
                if err:
                    with (app_root() / "mcp.log").open("a", encoding="utf-8") as fh:
                        fh.write(f"\n=== {dt.datetime.now().isoformat()} ===\n{err}\n")
        except Exception:
            with (app_root() / "mcp.log").open("a", encoding="utf-8") as fh:
                fh.write(f"\n=== {dt.datetime.now().isoformat()} (start) ===\n")
                fh.write(traceback.format_exc())

        app.mainloop()
    except Exception:
        import traceback

        log_path = app_root() / "crash.log"
        try:
            with log_path.open("a", encoding="utf-8") as fh:
                fh.write(f"\n=== {dt.datetime.now().isoformat()} (main) ===\n")
                fh.write(f"frozen={getattr(sys, 'frozen', False)}\n")
                fh.write(traceback.format_exc())
        except Exception:
            pass
        raise
    finally:
        # stopping the embedded server keeps the port free for the next run
        try:
            if app is not None and getattr(app, "mcp_host", None) is not None:
                app.mcp_host.stop()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

