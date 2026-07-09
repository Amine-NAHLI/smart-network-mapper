"""
gui/pages/dashboard.py
----------------------
Page « DASHBOARD » — vue d'ensemble du dernier scan.
"""

import os
import json
import tkinter as tk
import customtkinter as ctk

from gui.constants import *


class DashboardPage(ctk.CTkFrame):
    """Affiche les statistiques du dernier scan et un tableau des ports ouverts."""

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
        ctk.CTkLabel(lbl_box, text="[ ", font=self.app.FONT_MONO_LG, text_color=CYAN_ACCENT).pack(side="left")
        ctk.CTkLabel(lbl_box, text="DASHBOARD", font=self.app.FONT_MONO_LG, text_color=TEXT_PRIMARY).pack(side="left")
        ctk.CTkLabel(lbl_box, text=" ]", font=self.app.FONT_MONO_LG, text_color=CYAN_ACCENT).pack(side="left")

        # Stat cards
        cards_row = ctk.CTkFrame(self, fg_color="transparent")
        cards_row.pack(fill="x", padx=24, pady=20)
        for i in range(4):
            cards_row.grid_columnconfigure(i, weight=1)

        card_defs = [
            ("H O S T S   S C A N N E D", "stat_hosts", TEXT_PRIMARY),
            ("O P E N   P O R T S",       "stat_ports", TEXT_PRIMARY),
            ("V U L N E R A B L E",       "stat_vuln",  RED_DANGER),
            ("L A S T   S C A N",        "stat_date",  CYAN_ACCENT),
        ]
        for col, (label, attr, color) in enumerate(card_defs):
            card = ctk.CTkFrame(cards_row, fg_color=NAVY_CARD,
                                border_color=BORDER_COLOR, border_width=1, corner_radius=8)
            card.grid(row=0, column=col, padx=5, sticky="ew")
            ctk.CTkLabel(card, text=label, font=self.app.FONT_MONO_SM,
                         text_color=TEXT_MUTED).pack(anchor="w", padx=14, pady=(12, 2))

            val_font = self.app.FONT_MONO_XL if "DATE" not in label else self.app.FONT_MONO_LG
            lbl = ctk.CTkLabel(card, text="—", font=val_font, text_color=color)
            lbl.pack(anchor="w", padx=14, pady=(0, 12))
            setattr(self, attr, lbl)

        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.pack(fill="x", padx=24, pady=(0, 6))
        ctk.CTkButton(bar, text="[ REFRESH ]", font=self.app.FONT_MONO_MD,
                      fg_color="transparent", text_color=CYAN_ACCENT, border_color=CYAN_ACCENT,
                      border_width=1, hover_color=NAVY_SIDEBAR,
                      width=110, command=self.refresh).pack(side="right")

        # Top Area for Chart & Stats
        self.dash_top = ctk.CTkFrame(self, fg_color="transparent")
        self.dash_top.pack(fill="x", padx=24, pady=(0, 10))

        self.chart_canvas = tk.Canvas(self.dash_top, width=200, height=180,
                                      bg=NAVY_BLACK, highlightthickness=0)
        self.chart_canvas.pack(side="left")

        self.dash_scroll = ctk.CTkScrollableFrame(self, fg_color=NAVY_SIDEBAR,
                                                   border_color=BORDER_COLOR, border_width=1,
                                                   corner_radius=8)
        self.dash_scroll.pack(fill="both", expand=True, padx=24, pady=(0, 24))

    # ── Rafraîchissement ─────────────────────────────────────────

    def refresh(self):
        for w in self.dash_scroll.winfo_children():
            w.destroy()

        scan_path = self.app.scan_result_path()
        if not os.path.exists(scan_path):
            self._reset_stats()
            ctk.CTkLabel(self.dash_scroll,
                         text="No scan data found. Start a new scan.",
                         font=("Segoe UI", 12), text_color=GRAY).pack(expand=True, pady=50)
            return

        try:
            with open(scan_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            self._reset_stats()
            return

        ports      = data.get("ports", [])
        open_ports = [p for p in ports if p.get("statut") == "ouvert"]
        vuln_ports = [p for p in open_ports if p.get("vulnerable") == 1]

        self.stat_hosts.configure(text="1" if data.get("cible") else "0")
        self.stat_ports.configure(text=str(len(open_ports)))
        self.stat_vuln.configure(text=str(len(vuln_ports)))
        date_str = data.get("date", "—")
        self.stat_date.configure(text=date_str[:10] if date_str != "—" else "—")

        self._draw_chart(len(open_ports), len(vuln_ports))

        if not open_ports:
            ctk.CTkLabel(self.dash_scroll, text="No open ports in last scan.",
                         font=("Segoe UI", 11), text_color=GRAY).pack(pady=30)
            return

        cols   = ["PORT", "SERVICE", "VERSION", "STATUS", "AI", "CONFIDENCE"]
        widths = [60, 110, 160, 90, 130, 100]

        hdr = ctk.CTkFrame(self.dash_scroll, fg_color=BG_SIDE)
        hdr.pack(fill="x", pady=(4, 2))
        for c, w in zip(cols, widths):
            ctk.CTkLabel(hdr, text=c, font=("Courier New", 10),
                         text_color=GRAY, width=w, anchor="w").pack(side="left", padx=6)

        for p in open_ports:
            is_vuln = p.get("vulnerable") == 1
            row_bg  = "#1a0a0a" if is_vuln else "#0a1a0a"
            txt_col = RED if is_vuln else GREEN
            row = ctk.CTkFrame(self.dash_scroll, fg_color=row_bg, corner_radius=4)
            row.pack(fill="x", pady=1)
            conf = p.get("confidence")

            try:
                conf_val = float(conf)
                if conf_val <= 1:
                    conf_val *= 100
                conf_text = f"{conf_val:.1f}%"
            except (TypeError, ValueError):
                conf_text = "-"

            vals = [
                str(p.get("port", "")),
                p.get("service", ""),
                p.get("version", ""),
                p.get("statut", ""),
                p.get("label", ""),
                conf_text,
            ]
            for val, w in zip(vals, widths):
                ctk.CTkLabel(row, text=val, font=("Courier New", 10),
                             text_color=txt_col, width=w, anchor="w").pack(side="left", padx=6, pady=4)

    def _reset_stats(self):
        for attr in ("stat_hosts", "stat_ports", "stat_vuln", "stat_date"):
            getattr(self, attr).configure(text="—")
        self.chart_canvas.delete("all")

    def _draw_chart(self, open_count, vuln_count):
        cv = self.chart_canvas
        cv.delete("all")
        if open_count == 0:
            cv.create_text(100, 90, text="No Data", fill=TEXT_MUTED, font=("Consolas", 12))
            return

        safe_count = max(0, open_count - vuln_count)
        total = open_count
        vuln_angle = (vuln_count / total) * 359.9
        safe_angle = (safe_count / total) * 359.9

        cv.create_arc(10, 10, 170, 170, start=0, extent=safe_angle,
                      fill=GREEN_SUCCESS, outline=NAVY_BLACK, width=18, style="arc")
        cv.create_arc(10, 10, 170, 170, start=safe_angle, extent=vuln_angle,
                      fill=RED_DANGER, outline=NAVY_BLACK, width=18, style="arc")
        cv.create_text(90, 90, text=f"{int((safe_count/total)*100)}%\nSAFE",
                       fill=TEXT_PRIMARY, font=("Consolas", 10, "bold"), justify="center")