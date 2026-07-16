"""
app.py
------
Point d'entrée de Smart Network Mapper.

Ce fichier ne contient plus que le squelette de l'application :
  • Initialisation de la fenêtre principale
  • Barre latérale de navigation
  • Instanciation des pages (gui/pages/*)
  • Routage entre les pages

Toute la logique métier est déléguée aux modules :
  gui/pages/dashboard.py  — vue d'ensemble
  gui/pages/new_scan.py   — scan réseau
  gui/pages/results.py    — résultats détaillés
  gui/pages/history.py    — historique des scans (SQLite)
  gui/pages/about.py      — page d'information animée
  gui/db.py               — accès à la base de données SQLite
  gui/constants.py        — design-system tokens
"""

import sys
import os
import ctypes

try:
    import customtkinter as ctk
except ImportError:
    if getattr(sys, "frozen", False):
        raise
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "customtkinter"])
    import customtkinter as ctk

from tkinter import ttk, messagebox

from gui.constants import *
from gui import db
from gui.pages.dashboard import DashboardPage
import threading
from gui.pages.new_scan import NewScanPage
from gui.pages.results import ResultsPage
from gui.pages.history import HistoryPage
from gui.pages.about import AboutPage
from core.paths import get_outputs_dir, fix_frozen_stdio, configure_hf_download_env
from scanner.iana_manager import init_iana_database

fix_frozen_stdio()
configure_hf_download_env()
threading.Thread(target=init_iana_database, daemon=True).start()


def _scan_result_path():
    return os.path.join(get_outputs_dir(), "scan_result.json")



def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    if getattr(sys, "frozen", False):
        executable = sys.executable
        params = ""
    else:
        executable = sys.executable
        params = f'"{os.path.abspath(__file__)}"'

    try:
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            executable,
            params,
            None,
            1,
        )
        sys.exit(0)
    except Exception:
        # Si l'utilisateur refuse l'UAC, on continue en mode normal
        pass



# ════════════════════════════════════════════════════════════════
class SmartNetworkMapper(ctk.CTk):
    """Fenêtre principale — orchestrateur de navigation."""

    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title("SMART NETWORK MAPPER v1.0")
        self.after(0, lambda: self.state('zoomed'))
        self.configure(fg_color=NAVY_BLACK)

        # ── Treeview Style ──────────────────────────────────────
        self._setup_treeview_style()

        # ── Font Setup ──────────────────────────────────────────
        self.FONT_MONO_SM = ctk.CTkFont(family="Consolas", size=11)
        self.FONT_MONO_MD = ctk.CTkFont(family="Consolas", size=13)
        self.FONT_MONO_LG = ctk.CTkFont(family="Consolas", size=15, weight="bold")
        self.FONT_MONO_XL = ctk.CTkFont(family="Consolas", size=22, weight="bold")
        self.FONT_TITLE   = ctk.CTkFont(family="Consolas", size=28, weight="bold")

        # Navigation state
        self.active_page = None
        self.nav_buttons = {}
        self.nav_accents = {}

        # Shared scan state (written by NewScanPage, read by ResultsPage)
        self.shared_scan_results  = []
        self.shared_selected_ip   = None
        self.shared_scan_duration = 0.0

        # Initialiser la base de données SQLite
        db.init_db()

        # Build UI
        self._build_layout()
        self.show_page("DASHBOARD")

        if not is_admin():
            self.after(600, self._warn_admin)

    # ── Layout ──────────────────────────────────────────────────

    def _build_layout(self):
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_content()

    def _setup_treeview_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("SNM.Treeview",
            background=NAVY_CARD,
            foreground=TEXT_SECONDARY,
            fieldbackground=NAVY_CARD,
            rowheight=36,
            font=("Consolas", 11),
            borderwidth=0,
        )
        style.configure("SNM.Treeview.Heading",
            background=NAVY_SIDEBAR,
            foreground=TEXT_MUTED,
            font=("Consolas", 10, "bold"),
            relief="flat",
            borderwidth=0,
        )
        style.map("SNM.Treeview",
            background=[("selected", "#1E3A5F")],
            foreground=[("selected", CYAN_ACCENT)],
        )

    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=200, fg_color=SIDEBAR_LOGO_BG, corner_radius=0)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)
        sb.grid_columnconfigure(0, weight=1)
        sb.grid_rowconfigure(10, weight=1)

        ctk.CTkFrame(sb, width=1, fg_color=BORDER_COLOR).place(relx=1, rely=0, relheight=1, anchor="ne")

        ctk.CTkLabel(sb, text="[ SNM ]", font=self.FONT_TITLE,
                     text_color=CYAN_ACCENT).grid(row=0, column=0, padx=20, pady=(24, 2), sticky="w")
        ctk.CTkLabel(sb, text="Network Scanner", font=self.FONT_MONO_SM,
                     text_color=TEXT_MUTED).grid(row=1, column=0, padx=20, pady=(0, 10), sticky="w")

        sep = ctk.CTkFrame(sb, height=1, fg_color=BORDER_COLOR)
        sep.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 10))

        for i, page in enumerate(PAGES):
            btn_frame = ctk.CTkFrame(sb, fg_color="transparent", height=42)
            btn_frame.grid(row=3 + i, column=0, sticky="ew", pady=1)
            btn_frame.pack_propagate(False)

            accent = ctk.CTkFrame(btn_frame, width=3, fg_color="transparent", corner_radius=0)
            accent.pack(side="left", fill="y")
            self.nav_accents[page] = accent

            btn = ctk.CTkButton(
                btn_frame,
                text=f"   {PAGE_ICONS[page]}   {page}",
                font=self.FONT_MONO_MD,
                anchor="w",
                fg_color="transparent",
                hover_color=NAVY_SIDEBAR,
                text_color=TEXT_SECONDARY,
                corner_radius=0,
                height=42,
                command=lambda p=page: self.show_page(p),
            )
            btn.pack(side="left", fill="both", expand=True)
            self.nav_buttons[page] = btn

        ctk.CTkLabel(sb, text="v1.0.0 | Python", font=self.FONT_MONO_SM,
                     text_color=TEXT_MUTED).grid(row=10, column=0, padx=20, pady=16, sticky="sw")

    def _build_content(self):
        content = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        content.grid(row=0, column=1, sticky="nsew")
        content.grid_rowconfigure(0, weight=1)
        content.grid_columnconfigure(0, weight=1)

        self.pages = {
            "DASHBOARD": DashboardPage(content, self),
            "NEW SCAN":  NewScanPage(content, self),
            "RESULTS":   ResultsPage(content, self),
            "HISTORY":   HistoryPage(content, self),
            "ABOUT":     AboutPage(content, self),
        }
        for f in self.pages.values():
            f.grid(row=0, column=0, sticky="nsew")

    # ── Navigation ──────────────────────────────────────────────

    def show_page(self, name):
        # Stop about animations when leaving that page
        if self.active_page == "ABOUT" and name != "ABOUT":
            self.pages["ABOUT"].stop_anims()

        self.active_page = name
        for page, btn in self.nav_buttons.items():
            if page == name:
                btn.configure(text_color=CYAN_ACCENT, fg_color=NAVY_SIDEBAR)
                self.nav_accents[page].configure(fg_color=CYAN_ACCENT)
            else:
                btn.configure(text_color=TEXT_SECONDARY, fg_color="transparent")
                self.nav_accents[page].configure(fg_color="transparent")

        self.pages[name].tkraise()

        if name == "DASHBOARD":
            self.pages["DASHBOARD"].refresh()
        if name == "RESULTS":
            self.pages["RESULTS"].populate()
        if name == "HISTORY":
            self.pages["HISTORY"].refresh()
        if name == "ABOUT":
            self.pages["ABOUT"].start_anims()

    def scan_result_path(self):
        return _scan_result_path()

    def _warn_admin(self):
        messagebox.showwarning(
            "Administrator Required",
            "Run as Administrator for full Scapy features.\n"
            "Some scan functions may be limited.",
        )


# ════════════════════════════════════════════════════════════════

def run_app():
    app = SmartNetworkMapper()
    app.mainloop()


if __name__ == "__main__":
    if not is_admin() and os.name == "nt":
        relaunch_as_admin()
    run_app()
