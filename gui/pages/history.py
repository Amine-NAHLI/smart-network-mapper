"""
gui/pages/history.py
--------------------
Page « HISTORY » — historique persistant des scans (SQLite).

Nouvelle fonctionnalité permettant de consulter, charger ou supprimer
les résultats des scans précédents.
"""

import os
import json
import customtkinter as ctk
from tkinter import ttk, messagebox

from gui.constants import *
from gui import db


class HistoryPage(ctk.CTkFrame):
    """Liste tous les scans enregistrés dans la base SQLite locale."""

    def __init__(self, parent, app):
        super().__init__(parent, fg_color=NAVY_BLACK, corner_radius=0)
        self.app = app
        self._build()

    # ── Construction ─────────────────────────────────────────────

    def _build(self):
        # Top Bar
        top_bar = ctk.CTkFrame(self, height=56, fg_color=NAVY_BLACK, corner_radius=0)
        top_bar.pack(fill="x")
        ctk.CTkFrame(top_bar, height=1, fg_color=BORDER_COLOR).pack(side="bottom", fill="x")

        lbl_box = ctk.CTkFrame(top_bar, fg_color="transparent")
        lbl_box.pack(side="left", padx=24)
        ctk.CTkLabel(lbl_box, text="[ ", font=self.app.FONT_MONO_LG,
                     text_color=CYAN_ACCENT).pack(side="left")
        ctk.CTkLabel(lbl_box, text="HISTORY", font=self.app.FONT_MONO_LG,
                     text_color=TEXT_PRIMARY).pack(side="left")
        ctk.CTkLabel(lbl_box, text=" ]", font=self.app.FONT_MONO_LG,
                     text_color=CYAN_ACCENT).pack(side="left")

        # Action bar
        action_bar = ctk.CTkFrame(self, fg_color="transparent")
        action_bar.pack(fill="x", padx=24, pady=(16, 8))

        self.count_label = ctk.CTkLabel(action_bar, text="0 scan(s) enregistré(s)",
                                         font=self.app.FONT_MONO_SM, text_color=TEXT_SECONDARY)
        self.count_label.pack(side="left")

        ctk.CTkButton(action_bar, text="[ REFRESH ]", font=self.app.FONT_MONO_SM,
                      fg_color="transparent", text_color=CYAN_ACCENT,
                      border_color=CYAN_ACCENT, border_width=1,
                      hover_color=NAVY_SIDEBAR, width=100, height=32,
                      command=self.refresh).pack(side="right", padx=(8, 0))

        ctk.CTkButton(action_bar, text="[ CLEAR ALL ]", font=self.app.FONT_MONO_SM,
                      fg_color="transparent", text_color=RED_DANGER,
                      border_color=RED_DANGER, border_width=1,
                      hover_color="#1a0a0a", width=110, height=32,
                      command=self._clear_all).pack(side="right")

        # ── Table ────────────────────────────────────────────────
        table_wrap = ctk.CTkFrame(self, fg_color=NAVY_CARD,
                                   border_color=BORDER_COLOR, border_width=1,
                                   corner_radius=8)
        table_wrap.pack(fill="both", expand=True, padx=24, pady=(0, 12))

        self.tree = ttk.Treeview(table_wrap, style="SNM.Treeview", selectmode="browse")
        self.tree["columns"] = ("ID", "TARGET", "DATE", "DURATION",
                                "OPEN", "VULN", "TOTAL")
        self.tree.column("#0",       width=0,  stretch="no")
        self.tree.column("ID",       width=50, anchor="center")
        self.tree.column("TARGET",   width=140, anchor="w")
        self.tree.column("DATE",     width=160, anchor="w")
        self.tree.column("DURATION", width=90,  anchor="center")
        self.tree.column("OPEN",     width=80,  anchor="center")
        self.tree.column("VULN",     width=80,  anchor="center")
        self.tree.column("TOTAL",    width=80,  anchor="center")

        self.tree.heading("ID",       text="#")
        self.tree.heading("TARGET",   text="T A R G E T")
        self.tree.heading("DATE",     text="D A T E")
        self.tree.heading("DURATION", text="D U R A T I O N")
        self.tree.heading("OPEN",     text="O P E N")
        self.tree.heading("VULN",     text="V U L N")
        self.tree.heading("TOTAL",    text="T O T A L")

        self.tree.pack(side="left", fill="both", expand=True)

        tree_scroll = ctk.CTkScrollbar(table_wrap, command=self.tree.yview)
        tree_scroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=tree_scroll.set)

        self.tree.tag_configure("has_vuln", foreground=RED_DANGER)
        self.tree.tag_configure("safe",     foreground=GREEN_SUCCESS)
        self.tree.tag_configure("normal",   foreground=TEXT_SECONDARY)

        # ── Bottom buttons ───────────────────────────────────────
        btns = ctk.CTkFrame(self, fg_color="transparent")
        btns.pack(fill="x", padx=24, pady=(0, 16))

        ctk.CTkButton(btns, text="[ LOAD SCAN ]", font=self.app.FONT_MONO_MD,
                      fg_color=CYAN_ACCENT, text_color=NAVY_BLACK,
                      hover_color="#0099BB", corner_radius=4, height=36,
                      width=160, command=self._load_selected).pack(side="left", padx=(0, 8))

        ctk.CTkButton(btns, text="[ DELETE ]", font=self.app.FONT_MONO_MD,
                      fg_color="transparent", text_color=RED_DANGER,
                      border_color=RED_DANGER, border_width=1,
                      hover_color="#1a0a0a", corner_radius=4, height=36,
                      width=120, command=self._delete_selected).pack(side="left")

    # ── Refresh ──────────────────────────────────────────────────

    def refresh(self):
        """Recharge l'intégralité de la liste depuis la base SQLite."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        scans = db.get_all_scans()
        self.count_label.configure(text=f"{len(scans)} scan(s) enregistré(s)")

        for s in scans:
            vuln = s.get("vuln_ports", 0)
            tag = "has_vuln" if vuln > 0 else "safe"

            self.tree.insert("", "end", iid=str(s["id"]), values=(
                s["id"],
                s["target"],
                s["date"],
                f"{s['duration']:.1f}s",
                s["open_ports"],
                vuln,
                s["total_ports"],
            ), tags=(tag,))

    # ── Actions ──────────────────────────────────────────────────

    def _get_selected_id(self) -> int | None:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("History", "Select a scan first.")
            return None
        return int(sel[0])

    def _load_selected(self):
        """Charge le JSON d'un ancien scan dans la page RESULTS."""
        scan_id = self._get_selected_id()
        if scan_id is None:
            return

        scan = db.get_scan_by_id(scan_id)
        if not scan:
            messagebox.showwarning("History", "Scan not found in database.")
            return

        json_path = scan.get("json_path", "")
        if not json_path or not os.path.exists(json_path):
            messagebox.showwarning("History",
                                   "JSON result file not found on disk.\n"
                                   f"Expected: {json_path}")
            return

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            messagebox.showerror("History", f"Failed to read JSON:\n{e}")
            return

        # Injecter les données dans le contexte partagé de l'app
        self.app.shared_selected_ip   = data.get("cible", scan["target"])
        self.app.shared_scan_duration = data.get("duration_seconds", scan["duration"])
        self.app.shared_scan_results  = data.get("ports", [])

        # Naviguer vers la page RESULTS
        self.app.show_page("RESULTS")

    def _delete_selected(self):
        scan_id = self._get_selected_id()
        if scan_id is None:
            return

        confirm = messagebox.askyesno("Delete Scan",
                                       f"Delete scan #{scan_id} from history?")
        if not confirm:
            return

        db.delete_scan(scan_id)
        self.refresh()

    def _clear_all(self):
        confirm = messagebox.askyesno("Clear History",
                                       "Delete ALL scan history?\nThis cannot be undone.")
        if not confirm:
            return

        db.delete_all_scans()
        self.refresh()
