import sys

try:
    import customtkinter as ctk
except ImportError:
    if getattr(sys, "frozen", False):
        raise
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "customtkinter"])
    import customtkinter as ctk

import threading
import json
import os
import sys
import ctypes
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox
import webbrowser

from scanner.host_discovery import scan_subnet
from scanner.port_scanner import scan_tcp          # per-port, real-time results
from scanner.device_info import get_hostname_dns, get_mac_arp
from scanner.utils import detect_lan_config
from model.predictor import predict
from reporter.html_generator import generate_html_report
from snm_paths import get_outputs_dir, ensure_outputs_dir

from tkinter import ttk

# ── NEW DESIGN SYSTEM ──────────────────────────────────────────
NAVY_BLACK      = "#0A0F1C"
NAVY_SIDEBAR    = "#0F1729"
NAVY_CARD       = "#131E35"
CYAN_ACCENT     = "#00D4FF"
PURPLE_ACCENT   = "#7C3AED"
GREEN_SUCCESS   = "#10B981"
RED_DANGER      = "#EF4444"
AMBER_WARNING   = "#F59E0B"
TEXT_PRIMARY    = "#F1F5F9"
TEXT_SECONDARY  = "#94A3B8"
TEXT_MUTED      = "#475569"
BORDER_COLOR    = "#1E293B"
SIDEBAR_LOGO_BG = "#060C18"

# ── LEGACY COLORS (mapping for backward compatibility) ──────────
CYAN    = CYAN_ACCENT
RED     = RED_DANGER
GREEN   = GREEN_SUCCESS
BG_MAIN = NAVY_BLACK
BG_SIDE = NAVY_SIDEBAR
BORDER  = BORDER_COLOR
GRAY    = TEXT_SECONDARY
WHITE   = TEXT_PRIMARY

FAST_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
              993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090]

def _outputs_dir():
    return get_outputs_dir()


def _scan_result_path():
    return os.path.join(_outputs_dir(), "scan_result.json")

PAGES      = ["DASHBOARD", "NEW SCAN", "RESULTS", "ABOUT"]
PAGE_ICONS = {"DASHBOARD": "◈", "NEW SCAN": "◉", "RESULTS": "▣", "ABOUT": "◎"}


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ════════════════════════════════════════════════════════════════
class SmartNetworkMapper(ctk.CTk):

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
        self.FONT_MONO_SM  = ctk.CTkFont(family="Consolas", size=11)
        self.FONT_MONO_MD  = ctk.CTkFont(family="Consolas", size=13)
        self.FONT_MONO_LG  = ctk.CTkFont(family="Consolas", size=15, weight="bold")
        self.FONT_MONO_XL  = ctk.CTkFont(family="Consolas", size=22, weight="bold")
        self.FONT_TITLE    = ctk.CTkFont(family="Consolas", size=28, weight="bold")

        # Nav state
        self.active_page = None
        self.nav_buttons = {}
        self.nav_accents = {}

        # Blink state
        self._blink_state = True
        self._blink_job   = None

        # Scan state
        self.selected_ip      = None
        self.scan_results     = []
        self.scan_start_t     = 0.0
        self.scan_duration    = 0.0      # stored on completion
        self.discovered_hosts = []
        self._step2_shown     = False
        self._step3_shown     = False
        self._scanning        = False    # guard against double-launch

        # Tkinter vars
        self.cidr_var         = ctk.StringVar(value="")
        self.target_ip_var    = ctk.StringVar(value="")
        self.scan_mode_var    = ctk.StringVar(value="FAST")
        self.custom_ports_var = ctk.StringVar(value="")
        
        # Search & Filter vars
        self.res_search_var   = ctk.StringVar(value="")
        self.res_filter_var   = ctk.StringVar(value="ALL")

        # About page animation state
        self._about_grid_y        = 0
        self._about_scan_y        = 0.0
        self._about_glow_on       = True
        self._about_bullet_on     = True
        self._about_grid_job      = None
        self._about_scan_job      = None
        self._about_glow_job      = None
        self._about_bull_job      = None
        self._about_title_id      = None   # canvas item for animated glow layer
        self._about_canvas_w      = 1
        self._about_canvas_h      = 260
        self._about_cv            = None
        self._about_bullet_labels = []

        self._build_layout()
        self._show_page("DASHBOARD")

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
        sb.grid_rowconfigure(8, weight=1)

        # Sidebar Border Right
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
                command=lambda p=page: self._show_page(p),
            )
            btn.pack(side="left", fill="both", expand=True)
            self.nav_buttons[page] = btn

        ctk.CTkLabel(sb, text="v1.0.0 | Python", font=self.FONT_MONO_SM,
                     text_color=TEXT_MUTED).grid(row=8, column=0, padx=20, pady=16, sticky="sw")

    def _build_content(self):
        self.content = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        self.pages = {
            "DASHBOARD": self._build_dashboard(),
            "NEW SCAN":  self._build_new_scan(),
            "RESULTS":   self._build_results(),
            "ABOUT":     self._build_about(),
        }
        for f in self.pages.values():
            f.grid(row=0, column=0, sticky="nsew")

    # ── Navigation ──────────────────────────────────────────────

    def _show_page(self, name):
        # Stop about animations when leaving that page
        if self.active_page == "ABOUT" and name != "ABOUT":
            self._stop_about_anims()

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
            self._refresh_dashboard()
        if name == "RESULTS":
            self._populate_results_page()
        if name == "ABOUT":
            self._start_about_anims()

    def _warn_admin(self):
        messagebox.showwarning(
            "Administrator Required",
            "Run as Administrator for full Scapy features.\n"
            "Some scan functions may be limited.",
        )

    # ════════════════════════════════════════════════════════════
    #  PAGE 1 — DASHBOARD
    # ════════════════════════════════════════════════════════════

    def _build_dashboard(self):
        frame = ctk.CTkFrame(self.content, fg_color=NAVY_BLACK, corner_radius=0)

        # Top Bar
        top_bar = ctk.CTkFrame(frame, height=56, fg_color=NAVY_BLACK, corner_radius=0)
        top_bar.pack(fill="x")
        ctk.CTkFrame(top_bar, height=1, fg_color=BORDER_COLOR).pack(side="bottom", fill="x")
        
        lbl_box = ctk.CTkFrame(top_bar, fg_color="transparent")
        lbl_box.pack(side="left", padx=24)
        ctk.CTkLabel(lbl_box, text="[ ", font=self.FONT_MONO_LG, text_color=CYAN_ACCENT).pack(side="left")
        ctk.CTkLabel(lbl_box, text="DASHBOARD", font=self.FONT_MONO_LG, text_color=TEXT_PRIMARY).pack(side="left")
        ctk.CTkLabel(lbl_box, text=" ]", font=self.FONT_MONO_LG, text_color=CYAN_ACCENT).pack(side="left")

        # Stat cards
        cards_row = ctk.CTkFrame(frame, fg_color="transparent")
        cards_row.pack(fill="x", padx=24, pady=20)
        for i in range(4):
            cards_row.grid_columnconfigure(i, weight=1)

        card_defs = [
            ("H O S T S   S C A N N E D", "stat_hosts", TEXT_PRIMARY),
            ("O P E N   P O R T S",    "stat_ports", TEXT_PRIMARY),
            ("V U L N E R A B L E",    "stat_vuln",  RED_DANGER),
            ("L A S T   S C A N",     "stat_date",  CYAN_ACCENT),
        ]
        for col, (label, attr, color) in enumerate(card_defs):
            card = ctk.CTkFrame(cards_row, fg_color=NAVY_CARD,
                                border_color=BORDER_COLOR, border_width=1, corner_radius=8)
            card.grid(row=0, column=col, padx=5, sticky="ew")
            ctk.CTkLabel(card, text=label, font=self.FONT_MONO_SM,
                         text_color=TEXT_MUTED).pack(anchor="w", padx=14, pady=(12, 2))
            
            val_font = self.FONT_MONO_XL if "DATE" not in label else self.FONT_MONO_LG
            lbl = ctk.CTkLabel(card, text="—", font=val_font, text_color=color)
            lbl.pack(anchor="w", padx=14, pady=(0, 12))
            setattr(self, attr, lbl)

        bar = ctk.CTkFrame(frame, fg_color="transparent")
        bar.pack(fill="x", padx=24, pady=(0, 6))
        ctk.CTkButton(bar, text="[ REFRESH ]", font=self.FONT_MONO_MD,
                      fg_color="transparent", text_color=CYAN_ACCENT, border_color=CYAN_ACCENT,
                      border_width=1, hover_color=NAVY_SIDEBAR,
                      width=110, command=self._refresh_dashboard).pack(side="right")

        # Top Area for Chart & Stats
        self.dash_top = ctk.CTkFrame(frame, fg_color="transparent")
        self.dash_top.pack(fill="x", padx=24, pady=(0, 10))

        self.chart_canvas = tk.Canvas(self.dash_top, width=200, height=180, 
                                      bg=NAVY_BLACK, highlightthickness=0)
        self.chart_canvas.pack(side="left")

        self.dash_scroll = ctk.CTkScrollableFrame(frame, fg_color=NAVY_SIDEBAR,
                                                   border_color=BORDER_COLOR, border_width=1,
                                                   corner_radius=8)
        self.dash_scroll.pack(fill="both", expand=True, padx=24, pady=(0, 24))

        return frame

    def _refresh_dashboard(self):
        for w in self.dash_scroll.winfo_children():
            w.destroy()

        if not os.path.exists(_scan_result_path()):
            self._dash_reset_stats()
            ctk.CTkLabel(self.dash_scroll,
                         text="No scan data found. Start a new scan.",
                         font=("Segoe UI", 12), text_color=GRAY).pack(expand=True, pady=50)
            return

        try:
            with open(_scan_result_path(), "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            self._dash_reset_stats()
            return

        ports      = data.get("ports", [])
        open_ports = [p for p in ports if p.get("statut") == "ouvert"]
        vuln_ports = [p for p in open_ports if p.get("vulnerable") == 1]

        self.stat_hosts.configure(text="1" if data.get("cible") else "0")
        self.stat_ports.configure(text=str(len(open_ports)))
        self.stat_vuln.configure(text=str(len(vuln_ports)))
        date_str = data.get("date", "—")
        self.stat_date.configure(text=date_str[:10] if date_str != "—" else "—")

        # ── Draw Pie Chart ───────────────────────────────────────
        self._draw_dashboard_chart(len(open_ports), len(vuln_ports))

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
            conf = p.get("confidence", 0)
            vals = [
                str(p.get("port", "")),
                p.get("service", ""),
                p.get("version", ""),
                p.get("statut", ""),
                p.get("label", ""),
                f"{conf:.1f}%",
            ]
            for val, w in zip(vals, widths):
                ctk.CTkLabel(row, text=val, font=("Courier New", 10),
                             text_color=txt_col, width=w, anchor="w").pack(side="left", padx=6, pady=4)

    def _dash_reset_stats(self):
        for attr in ("stat_hosts", "stat_ports", "stat_vuln", "stat_date"):
            getattr(self, attr).configure(text="—")
        self.chart_canvas.delete("all")

    def _draw_dashboard_chart(self, open_count, vuln_count):
        cv = self.chart_canvas
        cv.delete("all")
        if open_count == 0:
            cv.create_text(100, 90, text="No Data", fill=TEXT_MUTED, font=("Consolas", 12))
            return

        safe_count = max(0, open_count - vuln_count)
        
        # Simple Pie Chart logic
        total = open_count
        vuln_angle = (vuln_count / total) * 359.9
        safe_angle = (safe_count / total) * 359.9

        # Draw safe (green)
        cv.create_arc(10, 10, 170, 170, start=0, extent=safe_angle, fill=GREEN_SUCCESS, outline=NAVY_BLACK, width=18, style="arc")
        # Draw vuln (red)
        cv.create_arc(10, 10, 170, 170, start=safe_angle, extent=vuln_angle, fill=RED_DANGER, outline=NAVY_BLACK, width=18, style="arc")

        # Center text
        cv.create_text(90, 90, text=f"{int((safe_count/total)*100)}%\nSAFE", fill=TEXT_PRIMARY, font=("Consolas", 10, "bold"), justify="center")

    # ════════════════════════════════════════════════════════════
    #  PAGE 2 — NEW SCAN
    # ════════════════════════════════════════════════════════════

    def _build_new_scan(self):
        outer = ctk.CTkFrame(self.content, fg_color=NAVY_BLACK, corner_radius=0)
        
        # Top Bar
        top_bar = ctk.CTkFrame(outer, height=56, fg_color=NAVY_BLACK, corner_radius=0)
        top_bar.pack(fill="x")
        ctk.CTkFrame(top_bar, height=1, fg_color=BORDER_COLOR).pack(side="bottom", fill="x")
        
        lbl_box = ctk.CTkFrame(top_bar, fg_color="transparent")
        lbl_box.pack(side="left", padx=24)
        ctk.CTkLabel(lbl_box, text="[ ", font=self.FONT_MONO_LG, text_color=CYAN_ACCENT).pack(side="left")
        ctk.CTkLabel(lbl_box, text="NEW SCAN", font=self.FONT_MONO_LG, text_color=TEXT_PRIMARY).pack(side="left")
        ctk.CTkLabel(lbl_box, text=" ]", font=self.FONT_MONO_LG, text_color=CYAN_ACCENT).pack(side="left")

        self._scan_scroll = ctk.CTkScrollableFrame(outer, fg_color=NAVY_BLACK)
        self._scan_scroll.pack(fill="both", expand=True)

        self._build_direct_scan(self._scan_scroll)
        self._build_step1(self._scan_scroll)
        self._build_step2(self._scan_scroll)
        self._build_step3(self._scan_scroll)

        return outer

    # ── Direct Scan — Single IP / External ──────────────────────

    def _build_direct_scan(self, parent):
        box = ctk.CTkFrame(parent, fg_color=NAVY_SIDEBAR, border_color=BORDER_COLOR,
                            border_width=1, corner_radius=8)
        box.pack(fill="x", padx=24, pady=(20, 10))

        ctk.CTkLabel(box, text="◆  QUICK SCAN — SINGLE TARGET",
                     font=self.FONT_MONO_SM, text_color=TEXT_MUTED).pack(anchor="w", padx=16, pady=(12, 4))
        ctk.CTkFrame(box, height=1, fg_color=BORDER_COLOR).pack(fill="x", padx=16, pady=(0, 8))

        row = ctk.CTkFrame(box, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(0, 16))

        ctk.CTkLabel(row, text="TARGET IP:", font=self.FONT_MONO_MD,
                     text_color=TEXT_SECONDARY).pack(side="left", padx=(0, 12))
        ctk.CTkEntry(row, width=280, placeholder_text="e.g. 8.8.8.8 or 192.168.1.1",
                     textvariable=self.target_ip_var,
                     fg_color=NAVY_CARD, border_color=BORDER_COLOR,
                     border_width=1, corner_radius=4,
                     font=self.FONT_MONO_MD).pack(side="left", padx=(0, 12))
        
        ctk.CTkButton(row, text="[ SELECT TARGET ]", font=self.FONT_MONO_MD,
                      fg_color=CYAN_ACCENT, text_color=NAVY_BLACK, hover_color="#0099BB",
                      corner_radius=4, height=36,
                      command=self._select_direct_target).pack(side="left")

    def _select_direct_target(self):
        ip = self.target_ip_var.get().strip()
        if not ip:
            messagebox.showwarning("Missing Input", "Enter a target IP address first.")
            return
        self._select_host(ip)

    # ── Step 1 — Network Configuration ──────────────────────────

    def _build_step1(self, parent):
        box = ctk.CTkFrame(parent, fg_color=NAVY_SIDEBAR, border_color=BORDER_COLOR,
                            border_width=1, corner_radius=8)
        box.pack(fill="x", padx=24, pady=(0, 10))

        ctk.CTkLabel(box, text="◆  STEP 1 — NETWORK CONFIGURATION",
                     font=self.FONT_MONO_SM, text_color=TEXT_MUTED).pack(anchor="w", padx=16, pady=(12, 4))
        ctk.CTkFrame(box, height=1, fg_color=BORDER_COLOR).pack(fill="x", padx=16, pady=(0, 8))

        row = ctk.CTkFrame(box, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(0, 12))

        ctk.CTkLabel(row, text="NETWORK CIDR:", font=self.FONT_MONO_MD,
                     text_color=TEXT_SECONDARY).pack(side="left", padx=(0, 12))
        ctk.CTkEntry(row, width=200, placeholder_text="192.168.1.0/24",
                     textvariable=self.cidr_var,
                     fg_color=NAVY_CARD, border_color=BORDER_COLOR,
                     border_width=1, corner_radius=4,
                     font=self.FONT_MONO_MD).pack(side="left", padx=(0, 12))
        ctk.CTkButton(row, text="[ AUTO DETECT ]", font=self.FONT_MONO_MD,
                      fg_color="transparent", text_color=CYAN_ACCENT, border_color=CYAN_ACCENT,
                      border_width=1, hover_color=NAVY_SIDEBAR, height=36,
                      command=self._auto_detect_cidr).pack(side="left", padx=(0, 12))
        ctk.CTkButton(row, text="[ DISCOVER HOSTS ]", font=self.FONT_MONO_MD,
                      fg_color=CYAN_ACCENT, text_color=NAVY_BLACK, hover_color="#0099BB",
                      corner_radius=4, height=36,
                      command=self._start_host_discovery).pack(side="left")

        self.discovery_status = ctk.CTkLabel(box, text="", font=self.FONT_MONO_SM,
                                              text_color=CYAN_ACCENT)
        self.discovery_status.pack(anchor="w", padx=16, pady=(0, 4))

        self.hosts_table_frame = ctk.CTkScrollableFrame(box, fg_color=NAVY_CARD,
                                                         height=180, corner_radius=6)
        self.hosts_table_frame.pack(fill="x", padx=16, pady=(0, 16))

    def _auto_detect_cidr(self):
        config = detect_lan_config()
        if config:
            self.cidr_var.set(config["cidr"])
        else:
            messagebox.showwarning("Auto Detect", "Could not detect local network.")

    def _start_host_discovery(self):
        cidr = self.cidr_var.get().strip()
        if not cidr:
            messagebox.showwarning("Missing Input", "Enter a network CIDR first.")
            return
        self.discovery_status.configure(text="●  Discovering hosts...")
        for w in self.hosts_table_frame.winfo_children():
            w.destroy()
        threading.Thread(target=self._run_host_discovery, args=(cidr,), daemon=True).start()

    def _run_host_discovery(self, cidr):
        try:
            hosts = scan_subnet(cidr)
            alive = [h for h in hosts if h.get("alive")]
        except Exception as e:
            self.after(0, lambda msg=str(e): self.discovery_status.configure(
                text=f"●  Error: {msg}", text_color=RED_DANGER))
            return
        self.discovered_hosts = alive
        self.after(0, self._on_hosts_discovered)

    def _on_hosts_discovered(self):
        hosts = self.discovered_hosts
        self.discovery_status.configure(
            text=f"●  Found {len(hosts)} alive host(s)." if hosts else "●  No alive hosts found.",
            text_color=GREEN_SUCCESS if hosts else AMBER_WARNING)

        for w in self.hosts_table_frame.winfo_children():
            w.destroy()

        if not hosts:
            ctk.CTkLabel(self.hosts_table_frame, text="No hosts responded on this network.",
                         text_color=TEXT_MUTED, font=self.FONT_MONO_MD).pack(pady=20)
            return

        cols   = ["IP ADDRESS", "HOSTNAME", "MAC ADDRESS", "LATENCY", "ACTION"]
        widths = [140, 200, 160, 80, 100]

        hdr = ctk.CTkFrame(self.hosts_table_frame, fg_color=NAVY_SIDEBAR)
        hdr.pack(fill="x", pady=(0, 2))
        for c, w in zip(cols, widths):
            ctk.CTkLabel(hdr, text=c, font=self.FONT_MONO_SM,
                         text_color=TEXT_MUTED, width=w, anchor="w").pack(side="left", padx=4)

        for h in hosts:
            ip  = h.get("ip", "")
            hn  = h.get("hostname") or "—"
            mac = h.get("mac") or "—"
            lat = f"{h.get('latency', 0):.1f}ms" if h.get("latency") else "—"

            row = ctk.CTkFrame(self.hosts_table_frame, fg_color=NAVY_CARD, corner_radius=4)
            row.pack(fill="x", pady=1)
            
            # Colored dot for alive host
            ctk.CTkLabel(row, text="●", text_color=GREEN_SUCCESS, font=self.FONT_MONO_SM).pack(side="left", padx=(8, 0))
            
            for val, w in zip([ip, hn, mac, lat], [130, 200, 160, 80]):
                ctk.CTkLabel(row, text=val, font=self.FONT_MONO_SM,
                             text_color=TEXT_PRIMARY, width=w, anchor="w").pack(side="left", padx=4, pady=3)
            
            ctk.CTkButton(row, text="[ SELECT ]", font=self.FONT_MONO_SM,
                          fg_color="transparent", text_color=CYAN_ACCENT, border_color=CYAN_ACCENT,
                          border_width=1, hover_color=NAVY_SIDEBAR, width=90, height=28,
                          command=lambda _ip=ip: self._select_host(_ip)).pack(side="right", padx=8)

    # ── Step 2 — Scan Configuration ─────────────────────────────

    def _build_step2(self, parent):
        self.step2_frame = ctk.CTkFrame(parent, fg_color=NAVY_SIDEBAR, border_color=BORDER_COLOR,
                                         border_width=1, corner_radius=8)

        ctk.CTkLabel(self.step2_frame, text="◆  STEP 2 — SCAN CONFIGURATION",
                     font=self.FONT_MONO_SM, text_color=TEXT_MUTED).pack(anchor="w", padx=16, pady=(12, 4))
        ctk.CTkFrame(self.step2_frame, height=1, fg_color=BORDER_COLOR).pack(fill="x", padx=16, pady=(0, 8))

        self.target_label = ctk.CTkLabel(self.step2_frame, text="TARGET: —",
                                          font=self.FONT_MONO_LG, text_color=CYAN_ACCENT)
        self.target_label.pack(anchor="w", padx=16, pady=(0, 10))

        self.scan_mode_btn = ctk.CTkSegmentedButton(
            self.step2_frame,
            values=["FAST", "FULL", "CUSTOM"],
            variable=self.scan_mode_var,
            font=self.FONT_MONO_MD,
            fg_color=NAVY_CARD,
            selected_color=CYAN_ACCENT,
            selected_hover_color="#0099BB",
            unselected_color=NAVY_CARD,
            unselected_hover_color=NAVY_SIDEBAR,
            text_color=TEXT_SECONDARY,
            corner_radius=4,
            command=self._on_scan_mode_change,
        )
        self.scan_mode_btn.pack(anchor="w", padx=16, pady=(0, 8))

        self._custom_wrap = ctk.CTkFrame(self.step2_frame, fg_color="transparent")
        self._custom_wrap.pack(fill="x", padx=16)

        self.custom_ports_entry = ctk.CTkEntry(
            self._custom_wrap,
            placeholder_text="e.g. 80,443,8080",
            textvariable=self.custom_ports_var,
            fg_color=NAVY_CARD, border_color=BORDER_COLOR,
            border_width=1, corner_radius=4,
            font=self.FONT_MONO_MD,
            width=300,
        )

        self.launch_btn = ctk.CTkButton(
            self.step2_frame,
            text="[ LAUNCH SCAN ]",
            font=self.FONT_MONO_MD,
            fg_color=CYAN_ACCENT,
            hover_color="#0099BB",
            text_color=NAVY_BLACK,
            corner_radius=4,
            width=200, height=36,
            command=self._launch_scan,
        )
        self.launch_btn.pack(pady=(10, 16))

    def _select_host(self, ip):
        self.selected_ip = ip
        self.target_label.configure(text=f"TARGET: {ip}")
        if not self._step2_shown:
            self.step2_frame.pack(fill="x", padx=24, pady=(0, 10))
            self._step2_shown = True

    def _on_scan_mode_change(self, val):
        if val == "CUSTOM":
            self.custom_ports_entry.pack(fill="x", pady=(0, 8))
        else:
            self.custom_ports_entry.pack_forget()

    def _get_ports_to_scan(self):
        mode = self.scan_mode_var.get()
        if mode == "FAST":
            return list(FAST_PORTS)
        if mode == "FULL":
            return list(range(1, 65536))
        raw = self.custom_ports_var.get().strip()
        try:
            ports = []
            for part in raw.split(","):
                part = part.strip()
                if not part: continue
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    ports.extend(range(start, end + 1))
                elif part.isdigit():
                    ports.append(int(part))
            return ports if ports else list(FAST_PORTS)
        except Exception:
            return list(FAST_PORTS)

    # ── Step 3 — Progress & Live Log ────────────────────────────

    def _build_step3(self, parent):
        self.step3_frame = ctk.CTkFrame(parent, fg_color=NAVY_SIDEBAR, border_color=BORDER_COLOR,
                                         border_width=1, corner_radius=8)

        self.scanning_label = ctk.CTkLabel(self.step3_frame, text="",
                                            font=self.FONT_MONO_LG, text_color=CYAN_ACCENT)
        self.scanning_label.pack(anchor="w", padx=16, pady=(12, 4))

        self.progress_bar = ctk.CTkProgressBar(self.step3_frame, mode="indeterminate",
                                                fg_color=BORDER_COLOR,
                                                progress_color=CYAN_ACCENT,
                                                corner_radius=2, height=4)
        self.progress_bar.pack(fill="x", padx=16, pady=(0, 12))

        self.log_frame = ctk.CTkScrollableFrame(self.step3_frame, fg_color="#050810",
                                                 height=220, corner_radius=6,
                                                 border_width=1, border_color=BORDER_COLOR)
        self.log_frame.pack(fill="x", padx=16, pady=(0, 12))

        self.view_results_btn = ctk.CTkButton(
            self.step3_frame,
            text="[ VIEW RESULTS ]",
            font=self.FONT_MONO_MD,
            fg_color=CYAN_ACCENT,
            text_color=NAVY_BLACK,
            hover_color="#0099BB",
            corner_radius=4, height=36,
            command=lambda: self._show_page("RESULTS"),
        )

    def _launch_scan(self):
        if self._scanning:
            return
        if not self.selected_ip:
            messagebox.showwarning("No Target", "Select a host first.")
            return

        ports = self._get_ports_to_scan()
        if not ports:
            messagebox.showwarning("No Ports", "No valid ports to scan.")
            return

        if not self._step3_shown:
            self.step3_frame.pack(fill="x", padx=24, pady=(0, 10))
            self._step3_shown = True

        self.view_results_btn.pack_forget()
        for w in self.log_frame.winfo_children():
            w.destroy()

        self._scanning = True
        self.launch_btn.configure(state="disabled", text="[ SCANNING... ]", fg_color=PURPLE_ACCENT)

        self.scan_results  = []
        self.scan_start_t  = time.time()
        self.scan_duration = 0.0

        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()
        self._start_blink(self.selected_ip)

        threading.Thread(
            target=self._run_port_scan,
            args=(self.selected_ip, ports),
            daemon=True,
        ).start()

    # ── Blink helpers ────────────────────────────────────────────

    def _start_blink(self, ip):
        if self._blink_job:
            self.after_cancel(self._blink_job)
        self._blink_state = True
        self._do_blink(ip)

    def _do_blink(self, ip):
        self._blink_state = not self._blink_state
        self.scanning_label.configure(
            text=f"SCANNING {ip}..." if self._blink_state else "")
        self._blink_job = self.after(500, lambda: self._do_blink(ip))

    def _stop_blink(self):
        if self._blink_job:
            self.after_cancel(self._blink_job)
            self._blink_job = None
        self.scanning_label.configure(text="SCAN COMPLETE")

    # ── Core scan thread ─────────────────────────────────────────

    def _run_port_scan(self, ip, ports):
        """Runs in a daemon thread. Uses scan_tcp per-port via as_completed
        so each result hits the UI live as it arrives."""
        total    = len(ports)
        done     = [0]
        enriched = []
        lock     = threading.Lock()

        max_workers = min(total, 300)

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(scan_tcp, ip, port): port for port in ports}

            for future in as_completed(futures):
                port_num = futures[future]
                try:
                    r = future.result()
                except Exception:
                    r = {
                        "port":    port_num,
                        "statut":  "erreur",
                        "service": "",
                        "version": "",
                        "banner":  "",
                    }

                # AI prediction on open ports
                if r.get("statut") == "ouvert":
                    try:
                        pred = predict(
                            port=r["port"],
                            version_string=r.get("version", ""),
                            service=r.get("service", ""),
                        )
                        r["vulnerable"] = pred["vulnerable"]
                        r["confidence"] = pred["confidence"]
                        r["label"]      = pred["label"]
                    except Exception:
                        r["vulnerable"] = 0
                        r["confidence"] = 0.0
                        r["label"]      = "—"
                else:
                    r["vulnerable"] = 0
                    r["confidence"] = 0.0
                    r["label"]      = "—"

                with lock:
                    enriched.append(r)
                    done[0] += 1
                    pct = done[0] / total

                # Schedule both UI updates together via after(0, ...)
                self.after(0, lambda p=pct: self._update_progress(p))
                self.after(0, lambda entry=dict(r): self._append_log(entry))

        self.scan_results = sorted(enriched, key=lambda x: x.get("port", 0))
        self.after(0, self._on_scan_complete)

    def _update_progress(self, pct):
        """Switch from indeterminate to determinate on first real value."""
        if self.progress_bar.cget("mode") == "indeterminate":
            self.progress_bar.stop()
            self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(pct)

    def _append_log(self, r):
        port   = r.get("port", "")
        statut = r.get("statut", "")
        svc    = r.get("service", "")
        ver    = r.get("version", "")
        conf   = r.get("confidence", 0)

        if statut == "ouvert":
            if r.get("vulnerable") == 1:
                color = RED
                txt = (f"[OPEN]   port {port:<6} {svc:<10} {ver:<18}"
                       f" → VULNÉRABLE ({conf*100:.1f}%)")
            else:
                color = GREEN
                txt = (f"[OPEN]   port {port:<6} {svc:<10} {ver:<18}"
                       f" → SAFE ({conf*100:.1f}%)")
        else:
            color = GRAY
            txt   = f"[{statut.upper():<7}] port {port:<6} {svc:<10}"

        ctk.CTkLabel(self.log_frame, text=txt, font=("Courier New", 10),
                     text_color=color, anchor="w").pack(fill="x", padx=4, pady=1)

    def _on_scan_complete(self):
        self._scanning = False
        self._stop_blink()
        self.progress_bar.stop()
        self.progress_bar.set(1.0)

        self.scan_duration = round(time.time() - self.scan_start_t, 1)
        self._save_result(self.selected_ip, self.scan_results, self.scan_duration)

        self.launch_btn.configure(state="normal", text="[ LAUNCH SCAN ]")
        self.view_results_btn.pack(pady=(4, 16))

        # Auto-refresh dashboard stats
        self._refresh_dashboard()

    def _save_result(self, ip, results, duration):
        ensure_outputs_dir()
        data = {
            "cible":            ip,
            "date":             datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": duration,
            "ports": [
                {
                    "port":       r.get("port"),
                    "protocole":  "TCP",
                    "statut":     r.get("statut"),
                    "service":    r.get("service", ""),
                    "version":    r.get("version", ""),
                    "vulnerable": r.get("vulnerable", 0),
                    "confidence": r.get("confidence", 0.0),
                    "label":      r.get("label", "—"),
                }
                for r in results
            ],
        }
        with open(_scan_result_path(), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
        # Génération automatique du rapport HTML Premium
        try:
            report_path = os.path.join(_outputs_dir(), "report.html")
            generate_html_report(data, report_path)
        except Exception:
            pass

    # ════════════════════════════════════════════════════════════
    #  PAGE 3 — RESULTS
    # ════════════════════════════════════════════════════════════

    def _build_results(self):
        frame = ctk.CTkFrame(self.content, fg_color=NAVY_BLACK, corner_radius=0)

        # Top Bar
        top_bar = ctk.CTkFrame(frame, height=56, fg_color=NAVY_BLACK, corner_radius=0)
        top_bar.pack(fill="x")
        ctk.CTkFrame(top_bar, height=1, fg_color=BORDER_COLOR).pack(side="bottom", fill="x")
        
        lbl_box = ctk.CTkFrame(top_bar, fg_color="transparent")
        lbl_box.pack(side="left", padx=24)
        ctk.CTkLabel(lbl_box, text="[ ", font=self.FONT_MONO_LG, text_color=CYAN_ACCENT).pack(side="left")
        ctk.CTkLabel(lbl_box, text="RESULTS", font=self.FONT_MONO_LG, text_color=TEXT_PRIMARY).pack(side="left")
        ctk.CTkLabel(lbl_box, text=" ]", font=self.FONT_MONO_LG, text_color=CYAN_ACCENT).pack(side="left")

        # Info bar
        info = ctk.CTkFrame(frame, fg_color=NAVY_SIDEBAR, border_color=BORDER_COLOR,
                             border_width=1, corner_radius=8)
        info.pack(fill="x", padx=24, pady=20)
        self.res_target = ctk.CTkLabel(info, text="TARGET: —",
                                        font=self.FONT_MONO_MD, text_color=CYAN_ACCENT)
        self.res_target.pack(side="left", padx=16, pady=10)
        self.res_date = ctk.CTkLabel(info, text="DATE: —",
                                      font=self.FONT_MONO_SM, text_color=TEXT_SECONDARY)
        self.res_date.pack(side="left", padx=12)
        self.res_dur = ctk.CTkLabel(info, text="DURATION: —",
                                     font=self.FONT_MONO_SM, text_color=TEXT_SECONDARY)
        self.res_dur.pack(side="left", padx=12)

        # Badges
        badges = ctk.CTkFrame(frame, fg_color="transparent")
        badges.pack(fill="x", padx=24, pady=(0, 12))
        self.badge_total = self._make_badge(badges, "TOTAL SCANNED", "—", TEXT_PRIMARY)
        self.badge_open  = self._make_badge(badges, "OPEN PORTS",    "—", CYAN_ACCENT)
        self.badge_vuln  = self._make_badge(badges, "VULNERABLE",    "—", RED_DANGER)
        self.badge_safe  = self._make_badge(badges, "SAFE",          "—", GREEN_SUCCESS)

        # Search & Filter bar
        sf_bar = ctk.CTkFrame(frame, fg_color="transparent")
        sf_bar.pack(fill="x", padx=24, pady=(0, 12))

        ctk.CTkLabel(sf_bar, text="🔍", font=self.FONT_MONO_MD, text_color=TEXT_MUTED).pack(side="left", padx=(0, 8))
        self.res_search_entry = ctk.CTkEntry(sf_bar, width=220, placeholder_text="Search ports, services...",
                                             textvariable=self.res_search_var, font=self.FONT_MONO_MD,
                                             fg_color=NAVY_CARD, border_color=BORDER_COLOR,
                                             border_width=1, corner_radius=4)
        self.res_search_entry.pack(side="left", padx=(0, 16))
        self.res_search_var.trace_add("write", lambda *args: self._populate_results_page())

        self.res_filter_btn = ctk.CTkSegmentedButton(
            sf_bar,
            values=["ALL", "OPEN", "VULNERABLE"],
            variable=self.res_filter_var,
            font=self.FONT_MONO_MD,
            fg_color=NAVY_CARD,
            selected_color=CYAN_ACCENT,
            selected_hover_color="#0099BB",
            unselected_color=NAVY_CARD,
            unselected_hover_color=NAVY_SIDEBAR,
            text_color=TEXT_SECONDARY,
            corner_radius=4,
            command=lambda v: self._populate_results_page(),
        )
        self.res_filter_btn.pack(side="left")

        # Table Section
        table_wrap = ctk.CTkFrame(frame, fg_color=NAVY_CARD,
                                   border_color=BORDER_COLOR, border_width=1, corner_radius=8)
        table_wrap.pack(fill="both", expand=True, padx=24, pady=(0, 12))

        # Use Treeview
        self.tree = ttk.Treeview(table_wrap, style="SNM.Treeview", selectmode="browse")
        self.tree["columns"] = ("PORT", "SERVICE", "VERSION", "STATUS", "LABEL", "CONF")
        self.tree.column("#0", width=0, stretch="no")
        self.tree.column("PORT", width=80, anchor="w")
        self.tree.column("SERVICE", width=120, anchor="w")
        self.tree.column("VERSION", width=150, anchor="w")
        self.tree.column("STATUS", width=100, anchor="w")
        self.tree.column("LABEL", width=120, anchor="w")
        self.tree.column("CONF", width=80, anchor="w")

        self.tree.heading("PORT", text="P O R T")
        self.tree.heading("SERVICE", text="S E R V I C E")
        self.tree.heading("VERSION", text="V E R S I O N")
        self.tree.heading("STATUS", text="S T A T U S")
        self.tree.heading("LABEL", text="A I   L A B E L")
        self.tree.heading("CONF", text="C O N F")

        self.tree.pack(side="left", fill="both", expand=True)

        self.tree_scroll = ctk.CTkScrollbar(table_wrap, command=self.tree.yview)
        self.tree_scroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=self.tree_scroll.set)

        self.tree.tag_configure("open",       foreground=GREEN_SUCCESS)
        self.tree.tag_configure("vulnerable", foreground=RED_DANGER)
        self.tree.tag_configure("filtered",   foreground=AMBER_WARNING)
        self.tree.tag_configure("closed",     foreground=TEXT_MUTED)

        # Legend
        legend = ctk.CTkFrame(frame, fg_color="transparent")
        legend.pack(fill="x", padx=24, pady=(0, 10))
        for txt, col in [("OPEN", GREEN_SUCCESS), ("VULNERABLE", RED_DANGER), ("FILTERED", AMBER_WARNING), ("CLOSED", TEXT_MUTED)]:
            lbl = ctk.CTkLabel(legend, text=f"● {txt}", font=self.FONT_MONO_SM, text_color=col)
            lbl.pack(side="left", padx=(0, 16))

        # Bottom buttons
        btns = ctk.CTkFrame(frame, fg_color="transparent")
        btns.pack(fill="x", padx=24, pady=(0, 16))
        
        ctk.CTkButton(btns, text="[ EXPORT JSON ]", font=self.FONT_MONO_MD,
                      fg_color="transparent", text_color=CYAN_ACCENT, border_color=CYAN_ACCENT,
                      border_width=1, hover_color=NAVY_SIDEBAR, height=36,
                      command=self._export_json).pack(side="left", padx=(0, 8))
        
        ctk.CTkButton(btns, text="[ DASHBOARD ]", font=self.FONT_MONO_MD,
                      fg_color="transparent", text_color=CYAN_ACCENT, border_color=CYAN_ACCENT,
                      border_width=1, hover_color=NAVY_SIDEBAR, height=36,
                      command=lambda: self._show_page("DASHBOARD")).pack(side="left", padx=(0, 8))
        
        ctk.CTkButton(btns, text="[ NEW SCAN ]", font=self.FONT_MONO_MD,
                      fg_color="transparent", text_color=CYAN_ACCENT, border_color=CYAN_ACCENT,
                      border_width=1, hover_color=NAVY_SIDEBAR, height=36,
                      command=lambda: self._show_page("NEW SCAN")).pack(side="left", padx=(0, 8))
        
        ctk.CTkButton(btns, text="[ VIEW HTML REPORT ]", font=self.FONT_MONO_MD,
                      fg_color=CYAN_ACCENT, text_color=NAVY_BLACK, hover_color="#0099BB",
                      corner_radius=4, height=36,
                      command=self._open_html_report).pack(side="right")

        return frame

    def _make_badge(self, parent, label, val, color):
        f = ctk.CTkFrame(parent, fg_color=NAVY_CARD, border_color=BORDER_COLOR,
                          border_width=1, corner_radius=8)
        f.pack(side="left", padx=(0, 8), fill="y")
        ctk.CTkLabel(f, text=label, font=self.FONT_MONO_SM,
                     text_color=TEXT_MUTED).pack(padx=14, pady=(8, 0))
        l = ctk.CTkLabel(f, text=val, font=self.FONT_MONO_LG, text_color=color)
        l.pack(padx=14, pady=(0, 8))
        return l

    def _populate_results_page(self):
        # Update Info
        self.res_target.configure(text=f"TARGET: {self.selected_ip}")
        date_now = datetime.now().strftime('%Y-%m-%d %H:%M')
        self.res_date.configure(text=f"DATE: {date_now}")
        self.res_dur.configure(text=f"DURATION: {self.scan_duration}s")

        # Clear Tree
        for item in self.tree.get_children():
            self.tree.delete(item)

        res = self.scan_results
        query = self.res_search_var.get().lower()
        mode  = self.res_filter_var.get()

        filtered = []
        for r in res:
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

        # Sort: Vulnerable first, then by port
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

        # Update Badges
        open_count = len([x for x in filtered if x.get("statut") == "ouvert"])
        vuln_count = len([x for x in filtered if x.get("vulnerable") == 1])
        self.badge_total.configure(text=str(len(filtered)))
        self.badge_open.configure(text=str(open_count))
        self.badge_vuln.configure(text=str(vuln_count))
        self.badge_safe.configure(text=str(max(0, open_count - vuln_count)))

    # ════════════════════════════════════════════════════════════
    #  PAGE 4 — ABOUT
    # ════════════════════════════════════════════════════════════

    # ════════════════════════════════════════════════════════════
    #  PAGE 4 — ABOUT  (cyberpunk 3-D canvas design)
    # ════════════════════════════════════════════════════════════

    def _build_about(self):
        frame = ctk.CTkFrame(self.content, fg_color=NAVY_BLACK, corner_radius=0)

        # ── Animated canvas header ───────────────────────────────
        self._about_cv = tk.Canvas(frame, height=260, bg=NAVY_BLACK,
                                    highlightthickness=0)
        self._about_cv.pack(fill="x")
        self._about_cv.bind("<Configure>",
                             lambda e: self._about_draw_static(e.width, e.height))

        # ── Scrollable info section ──────────────────────────────
        scroll = ctk.CTkScrollableFrame(frame, fg_color=NAVY_BLACK, corner_radius=0)
        scroll.pack(fill="both", expand=True)

        center = ctk.CTkFrame(scroll, fg_color="transparent")
        center.pack(pady=(20, 0))

        ctk.CTkLabel(center, text="Smart Network Mapper",
                     font=self.FONT_TITLE, text_color=TEXT_PRIMARY).pack()
        ctk.CTkLabel(center, text="AI-Powered Vulnerability Scanner",
                     font=self.FONT_MONO_MD, text_color=CYAN_ACCENT).pack(pady=(4, 14))

        ctk.CTkFrame(center, height=1, fg_color=BORDER_COLOR).pack(fill="x", padx=60, pady=(0, 20))

        # ── 3 Info cards ─────────────────────────────────────────
        cards_row = ctk.CTkFrame(center, fg_color="transparent")
        cards_row.pack(pady=(0, 20))
        for label, value in [("VERSION", "1.0.0"),
                              ("AUTHOR",  "Amine Nahli"),
                              ("LICENSE", "MIT / ACADEMIC")]:
            cv = tk.Canvas(cards_row, width=180, height=82,
                           bg=NAVY_BLACK, highlightthickness=0)
            cv.pack(side="left", padx=10)
            # Drop-shadow
            cv.create_rectangle(4, 4, 180, 82, fill="#003344", outline="")
            # Card body
            cv.create_rectangle(0, 0, 175, 77, fill=NAVY_SIDEBAR, outline="")
            # Glowing border
            cv.create_rectangle(1, 1, 174, 76, fill="", outline=CYAN_ACCENT, width=1)
            # Label + value
            cv.create_text(87, 26, text=label, fill=TEXT_MUTED,
                           font=("Consolas", 9, "bold"))
            cv.create_text(87, 52, text=value, fill=TEXT_PRIMARY,
                           font=("Consolas", 14, "bold"))

        # ── Tech badges (rounded-rect canvas) ────────────────────
        techs   = ["Python 3.13", "CustomTkinter", "Scapy", "Deep Learning", "Threading"]
        pad_x, pad_y, gap = 16, 6, 10
        badge_h = 32
        # Pre-compute badge widths
        b_widths = [int(len(t) * 8.2) + pad_x * 2 for t in techs]
        total_w  = sum(b_widths) + gap * (len(techs) - 1) + 2
        badges_cv = tk.Canvas(center, width=total_w, height=badge_h + pad_y * 2,
                               bg=NAVY_BLACK, highlightthickness=0)
        badges_cv.pack(pady=(0, 24))
        x = 1
        for tech, bw in zip(techs, b_widths):
            self._draw_rounded_rect(badges_cv, x, pad_y,
                                     x + bw, pad_y + badge_h,
                                     r=6, fill=NAVY_SIDEBAR, outline=CYAN_ACCENT, width=1)
            badges_cv.create_text(x + bw // 2, pad_y + badge_h // 2,
                                   text=tech, fill=CYAN_ACCENT,
                                   font=("Consolas", 10))
            x += bw + gap

        # ── Feature bullets ──────────────────────────────────────
        ctk.CTkLabel(center, text="[ CORE CAPABILITIES ]", font=self.FONT_MONO_MD,
                     text_color=TEXT_MUTED).pack(anchor="w", padx=80, pady=(0, 12))
        
        self._about_bullet_labels = []
        features = [
            "Ultra-fast asynchronous port scanning engine",
            "Deep packet inspection and service finger-printing",
            "AI-powered vulnerability assessment (Random Forest)",
            "Live host discovery and network mapping",
            "Premium HTML report generation and JSON exports",
        ]
        for feat in features:
            row = ctk.CTkFrame(center, fg_color="transparent")
            row.pack(anchor="w", padx=80, pady=4)
            bullet = ctk.CTkLabel(row, text="◆", font=("Segoe UI", 14),
                                   text_color=CYAN_ACCENT)
            bullet.pack(side="left", padx=(0, 12))
            ctk.CTkLabel(row, text=feat, font=self.FONT_MONO_MD,
                         text_color=TEXT_SECONDARY).pack(side="left")
            self._about_bullet_labels.append(bullet)

        ctk.CTkFrame(center, height=40, fg_color="transparent").pack()
        return frame

    # ── Canvas drawing helpers ───────────────────────────────────

    @staticmethod
    def _draw_rounded_rect(canvas, x1, y1, x2, y2, r=8, **kw):
        pts = [x1+r, y1,  x2-r, y1,
               x2,   y1,  x2,   y1+r,
               x2,   y2-r,x2,   y2,
               x2-r, y2,  x1+r, y2,
               x1,   y2,  x1,   y2-r,
               x1,   y1+r,x1,   y1]
        canvas.create_polygon(pts, smooth=True, **kw)

    def _about_draw_static(self, w, h):
        """Full redraw of the animated canvas. Called on Configure + resize."""
        if w <= 1 or h <= 1:
            return
        self._about_canvas_w = w
        self._about_canvas_h = h
        cv = self._about_cv
        cv.delete("all")

        gs = 40   # grid spacing

        # Vertical grid lines (static)
        for x in range(0, w + gs, gs):
            cv.create_line(x, 0, x, h, fill="#003344", stipple="gray25", tags="grid_v")

        # Horizontal grid lines (redrawn each animation tick)
        self._about_redraw_grid_h()

        # 3-D "SNM" title
        cx, cy = w // 2, h // 2 - 10
        font = ("Consolas", 84, "bold")
        for offset, color in [(6, "#001122"), (5, "#002233"),
                               (4, "#003344"), (3, "#004455"),
                               (2, "#005566"), (1, "#007788")]:
            cv.create_text(cx + offset, cy + offset, text="SNM",
                           fill=color, font=font, anchor="center")

        # Top (animated glow) layer
        glow = CYAN_ACCENT if self._about_glow_on else "#00AAAA"
        self._about_title_id = cv.create_text(cx, cy, text="SNM",
                                               fill=glow, font=font,
                                               anchor="center", tags="title_top")

        # Subtitle
        cv.create_text(cx, cy + 64, text="S M A R T   N E T W O R K   M A P P E R",
                       fill=TEXT_MUTED, font=("Consolas", 14), anchor="center")

        # Scan line
        cv.create_line(0, 0, w, 0, fill=CYAN_ACCENT, width=2, tags="scanline")
        self._about_scan_y = 0.0

    def _about_redraw_grid_h(self):
        """Redraw only the moving horizontal grid lines."""
        cv = self._about_cv
        if not cv: return
        w, h = self._about_canvas_w, self._about_canvas_h
        if w <= 1: return
        gs = 40
        cv.delete("grid_h")
        offset = int(self._about_grid_y) % gs
        y = offset - gs
        while y < h + gs:
            cv.create_line(0, y, w, y, fill="#003344", stipple="gray25", tags="grid_h")
            y += gs

    # ── Animation loops ──────────────────────────────────────────

    def _about_animate_grid(self):
        if self.active_page != "ABOUT": return
        self._about_grid_y = (self._about_grid_y + 1) % 40
        self._about_redraw_grid_h()
        self._about_grid_job = self.after(50, self._about_animate_grid)

    def _about_animate_scanline(self):
        if self.active_page != "ABOUT": return
        h = self._about_canvas_h
        w = self._about_canvas_w
        self._about_scan_y += 2.5
        if self._about_scan_y > h + 5:
            self._about_scan_y = -5.0
        y = int(self._about_scan_y)
        try:
            self._about_cv.coords("scanline", 0, y, w, y)
        except: pass
        self._about_scan_job = self.after(16, self._about_animate_scanline)

    def _about_animate_glow(self):
        if self.active_page != "ABOUT": return
        self._about_glow_on = not self._about_glow_on
        color = CYAN_ACCENT if self._about_glow_on else "#00AAAA"
        try:
            if self._about_title_id:
                self._about_cv.itemconfig(self._about_title_id, fill=color)
        except: pass
        self._about_glow_job = self.after(750, self._about_animate_glow)

    def _about_animate_bullets(self):
        if self.active_page != "ABOUT": return
        self._about_bullet_on = not self._about_bullet_on
        color = CYAN_ACCENT if self._about_bullet_on else TEXT_PRIMARY
        for lbl in self._about_bullet_labels:
            try: lbl.configure(text_color=color)
            except: pass
        self._about_bull_job = self.after(1000, self._about_animate_bullets)

    def _start_about_anims(self):
        self._stop_about_anims()
        self._about_animate_grid()
        self._about_animate_scanline()
        self._about_animate_glow()
        self._about_animate_bullets()

    def _stop_about_anims(self):
        for attr in ("_about_grid_job", "_about_scan_job",
                     "_about_glow_job", "_about_bull_job"):
            job = getattr(self, attr, None)
            if job:
                try: self.after_cancel(job)
                except: pass
                setattr(self, attr, None)

    def _open_html_report(self):
        report_path = os.path.abspath(os.path.join(_outputs_dir(), "report.html"))
        if os.path.exists(report_path):
            webbrowser.open(f"file://{report_path}")
        else:
            messagebox.showinfo("Report", "No HTML report found. Run a scan first.")

    def _export_json(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile="scan_result.json",
        )
        if not path:
            return
        if os.path.exists(_scan_result_path()):
            with open(_scan_result_path(), "r", encoding="utf-8") as f:
                data = f.read()
            with open(path, "w", encoding="utf-8") as f:
                f.write(data)
            messagebox.showinfo("Export", f"Saved to:\n{path}")
        else:
            messagebox.showwarning("Export", "No scan data to export.")


def run_app():
    app = SmartNetworkMapper()
    app.mainloop()


# ════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    run_app()
