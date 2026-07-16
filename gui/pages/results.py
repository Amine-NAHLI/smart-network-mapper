"""
gui/pages/results.py
--------------------
Page « RESULTS » — affichage détaillé des résultats du scan.
"""

import os
import json
import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox
import webbrowser
from datetime import datetime

from gui.constants import *
from core.paths import get_outputs_dir


class ResultsPage(ctk.CTkFrame):
    """Tableau Treeview triable, filtrable, avec export JSON et rapport HTML."""

    def __init__(self, parent, app):
        super().__init__(parent, fg_color=NAVY_BLACK, corner_radius=0)
        self.app = app

        # Search & Filter vars
        self.res_search_var = ctk.StringVar(value="")
        self.res_filter_var = ctk.StringVar(value="ALL")

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
        ctk.CTkLabel(lbl_box, text="RESULTS", font=self.app.FONT_MONO_LG, text_color=TEXT_PRIMARY).pack(side="left")
        ctk.CTkLabel(lbl_box, text=" ]", font=self.app.FONT_MONO_LG, text_color=CYAN_ACCENT).pack(side="left")

        # Info bar
        info = ctk.CTkFrame(self, fg_color=NAVY_SIDEBAR, border_color=BORDER_COLOR,
                             border_width=1, corner_radius=8)
        info.pack(fill="x", padx=24, pady=20)
        self.res_target = ctk.CTkLabel(info, text="TARGET: —",
                                        font=self.app.FONT_MONO_MD, text_color=CYAN_ACCENT)
        self.res_target.pack(side="left", padx=16, pady=10)
        self.res_date = ctk.CTkLabel(info, text="DATE: —",
                                      font=self.app.FONT_MONO_SM, text_color=TEXT_SECONDARY)
        self.res_date.pack(side="left", padx=12)
        self.res_dur = ctk.CTkLabel(info, text="DURATION: —",
                                     font=self.app.FONT_MONO_SM, text_color=TEXT_SECONDARY)
        self.res_dur.pack(side="left", padx=12)

        # Badges
        badges = ctk.CTkFrame(self, fg_color="transparent")
        badges.pack(fill="x", padx=24, pady=(0, 12))
        self.badge_total = self._make_badge(badges, "TOTAL SCANNED", "—", TEXT_PRIMARY)
        self.badge_open  = self._make_badge(badges, "OPEN PORTS",    "—", CYAN_ACCENT)
        self.badge_vuln  = self._make_badge(badges, "VULNERABLE",    "—", RED_DANGER)
        self.badge_safe  = self._make_badge(badges, "SAFE",          "—", GREEN_SUCCESS)

        # Search & Filter bar
        sf_bar = ctk.CTkFrame(self, fg_color="transparent")
        sf_bar.pack(fill="x", padx=24, pady=(0, 12))

        ctk.CTkLabel(sf_bar, text="🔍", font=self.app.FONT_MONO_MD, text_color=TEXT_MUTED).pack(side="left", padx=(0, 8))
        self.res_search_entry = ctk.CTkEntry(sf_bar, width=220, placeholder_text="Search ports, services...",
                                             textvariable=self.res_search_var, font=self.app.FONT_MONO_MD,
                                             fg_color=NAVY_CARD, border_color=BORDER_COLOR,
                                             border_width=1, corner_radius=4)
        self.res_search_entry.pack(side="left", padx=(0, 16))
        self.res_search_var.trace_add("write", lambda *args: self.populate())

        self.res_filter_btn = ctk.CTkSegmentedButton(
            sf_bar,
            values=["ALL", "OPEN", "VULNERABLE"],
            variable=self.res_filter_var,
            font=self.app.FONT_MONO_MD,
            fg_color=NAVY_CARD,
            selected_color=CYAN_ACCENT,
            selected_hover_color="#0099BB",
            unselected_color=NAVY_CARD,
            unselected_hover_color=NAVY_SIDEBAR,
            text_color=TEXT_SECONDARY,
            corner_radius=4,
            command=lambda v: self.populate(),
        )
        self.res_filter_btn.pack(side="left")

        # Table Section
        table_wrap = ctk.CTkFrame(self, fg_color=NAVY_CARD,
                                   border_color=BORDER_COLOR, border_width=1, corner_radius=8)
        table_wrap.pack(fill="both", expand=True, padx=24, pady=(0, 12))

        self.tree = ttk.Treeview(table_wrap, style="SNM.Treeview", selectmode="browse")
        self.tree["columns"] = ("PORT", "SERVICE", "VERSION", "STATUS", "LABEL", "CONF")
        self.tree.column("#0", width=0, stretch="no")
        self.tree.column("PORT",    width=80,  anchor="w")
        self.tree.column("SERVICE", width=120, anchor="w")
        self.tree.column("VERSION", width=150, anchor="w")
        self.tree.column("STATUS",  width=100, anchor="w")
        self.tree.column("LABEL",   width=120, anchor="w")
        self.tree.column("CONF",    width=80,  anchor="w")

        self.tree.heading("PORT",    text="P O R T")
        self.tree.heading("SERVICE", text="S E R V I C E")
        self.tree.heading("VERSION", text="V E R S I O N")
        self.tree.heading("STATUS",  text="S T A T U S")
        self.tree.heading("LABEL",   text="A I   L A B E L")
        self.tree.heading("CONF",    text="C O N F")

        self.tree.pack(side="left", fill="both", expand=True)

        self.tree_scroll = ctk.CTkScrollbar(table_wrap, command=self.tree.yview)
        self.tree_scroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=self.tree_scroll.set)

        self.tree.tag_configure("open",       foreground=GREEN_SUCCESS)
        self.tree.tag_configure("vulnerable", foreground=RED_DANGER)
        self.tree.tag_configure("filtered",   foreground=AMBER_WARNING)
        self.tree.tag_configure("closed",     foreground=TEXT_MUTED)

        # Legend
        legend = ctk.CTkFrame(self, fg_color="transparent")
        legend.pack(fill="x", padx=24, pady=(0, 10))
        for txt, col in [("OPEN", GREEN_SUCCESS), ("VULNERABLE", RED_DANGER),
                         ("FILTERED", AMBER_WARNING), ("CLOSED", TEXT_MUTED)]:
            lbl = ctk.CTkLabel(legend, text=f"● {txt}", font=self.app.FONT_MONO_SM, text_color=col)
            lbl.pack(side="left", padx=(0, 16))

        # Bottom buttons
        btns = ctk.CTkFrame(self, fg_color="transparent")
        btns.pack(fill="x", padx=24, pady=(0, 16))

        ctk.CTkButton(btns, text="[ EXPORT JSON ]", font=self.app.FONT_MONO_MD,
                      fg_color="transparent", text_color=CYAN_ACCENT, border_color=CYAN_ACCENT,
                      border_width=1, hover_color=NAVY_SIDEBAR, height=36,
                      command=self._export_json).pack(side="left", padx=(0, 8))

        ctk.CTkButton(btns, text="[ DASHBOARD ]", font=self.app.FONT_MONO_MD,
                      fg_color="transparent", text_color=CYAN_ACCENT, border_color=CYAN_ACCENT,
                      border_width=1, hover_color=NAVY_SIDEBAR, height=36,
                      command=lambda: self.app.show_page("DASHBOARD")).pack(side="left", padx=(0, 8))

        ctk.CTkButton(btns, text="[ NEW SCAN ]", font=self.app.FONT_MONO_MD,
                      fg_color="transparent", text_color=CYAN_ACCENT, border_color=CYAN_ACCENT,
                      border_width=1, hover_color=NAVY_SIDEBAR, height=36,
                      command=lambda: self.app.show_page("NEW SCAN")).pack(side="left", padx=(0, 8))

        ctk.CTkButton(btns, text="[ VIEW HTML REPORT ]", font=self.app.FONT_MONO_MD,
                      fg_color=CYAN_ACCENT, text_color=NAVY_BLACK, hover_color="#0099BB",
                      corner_radius=4, height=36,
                      command=self._open_html_report).pack(side="right")

    # ── Helpers ──────────────────────────────────────────────────

    def _make_badge(self, parent, label, val, color):
        f = ctk.CTkFrame(parent, fg_color=NAVY_CARD, border_color=BORDER_COLOR,
                          border_width=1, corner_radius=8)
        f.pack(side="left", padx=(0, 8), fill="y")
        ctk.CTkLabel(f, text=label, font=self.app.FONT_MONO_SM,
                     text_color=TEXT_MUTED).pack(padx=14, pady=(8, 0))
        l = ctk.CTkLabel(f, text=val, font=self.app.FONT_MONO_LG, text_color=color)
        l.pack(padx=14, pady=(0, 8))
        return l

    # ── Populate / Refresh ───────────────────────────────────────

    def populate(self):
        ip       = getattr(self.app, "shared_selected_ip", None)
        results  = getattr(self.app, "shared_scan_results", [])
        duration = getattr(self.app, "shared_scan_duration", 0)

        self.res_target.configure(text=f"TARGET: {ip or '—'}")
        date_now = datetime.now().strftime('%Y-%m-%d %H:%M')
        self.res_date.configure(text=f"DATE: {date_now}")
        self.res_dur.configure(text=f"DURATION: {duration}s")

        # Clear Tree
        for item in self.tree.get_children():
            self.tree.delete(item)

        query = self.res_search_var.get().lower()
        mode  = self.res_filter_var.get()

        filtered = []
        for r in results:
            port = str(r.get("port"))
            svc  = r.get("service", "").lower()
            ver  = r.get("version", "").lower()
            stat = r.get("statut", "").lower()
            lbl  = r.get("label", "").lower()

            if query and not any(query in x for x in [port, svc, ver, lbl]):
                continue
            if mode == "OPEN" and stat != "ouvert":
                continue
            if mode == "VULNERABLE" and r.get("vulnerable") != 1:
                continue
            filtered.append(r)

        filtered.sort(key=lambda x: (-(x.get("vulnerable", 0)), x.get("port", 0)))

        for r in filtered:
            is_vuln = r.get("vulnerable") == 1
            stat    = r.get("statut", "")
            tag     = "closed"
            if stat == "ouvert":
                tag = "vulnerable" if is_vuln else "open"
            elif stat == "filtré":
                tag = "filtered"

            self.tree.insert("", "end", values=(
                r.get("port"),
                r.get("service"),
                r.get("version"),
                stat.upper(),
                r.get("label"),
                f"{r.get('confidence', 0)*100:.1f}%"
            ), tags=(tag,))

        open_count = len([x for x in filtered if x.get("statut") == "ouvert"])
        vuln_count = len([x for x in filtered if x.get("vulnerable") == 1])
        self.badge_total.configure(text=str(len(filtered)))
        self.badge_open.configure(text=str(open_count))
        self.badge_vuln.configure(text=str(vuln_count))
        self.badge_safe.configure(text=str(max(0, open_count - vuln_count)))

    def _open_html_report(self):
        report_path = os.path.abspath(os.path.join(get_outputs_dir(), "report.html"))
        if os.path.exists(report_path):
            webbrowser.open(f"file://{report_path}")
        else:
            messagebox.showinfo("Report", "No HTML report found. Run a scan first.")

    def _export_json(self):
        src = os.path.join(get_outputs_dir(), "scan_result.json")
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile="scan_result.json",
        )
        if not path:
            return
        if os.path.exists(src):
            with open(src, "r", encoding="utf-8") as f:
                data = f.read()
            with open(path, "w", encoding="utf-8") as f:
                f.write(data)
            messagebox.showinfo("Export", f"Saved to:\n{path}")
        else:
            messagebox.showwarning("Export", "No scan data to export.")
