try:
    import customtkinter as ctk
except ImportError:
    import subprocess, sys
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
from tkinter import filedialog, messagebox

from scanner.host_discovery import scan_subnet
from scanner.port_scanner import scan_tcp          # per-port, real-time results
from scanner.device_info import get_hostname_dns, get_mac_arp
from scanner.utils import detect_lan_config
from model.predictor import predict

# ── Palette ─────────────────────────────────────────────────────
CYAN    = "#00f5ff"
RED     = "#ff0040"
GREEN   = "#00ff88"
BG_MAIN = "#0a0e1a"
BG_SIDE = "#0d1117"
BORDER  = "#1a2332"
GRAY    = "#4a5568"
WHITE   = "#e2e8f0"

FAST_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
              993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090]

OUTPUTS_DIR      = "outputs"
SCAN_RESULT_PATH = os.path.join(OUTPUTS_DIR, "scan_result.json")

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
        self.configure(fg_color=BG_MAIN)

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
        self.scan_mode_var    = ctk.StringVar(value="FAST")
        self.custom_ports_var = ctk.StringVar(value="")

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

    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=200, fg_color=BG_SIDE, corner_radius=0)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)
        sb.grid_columnconfigure(0, weight=1)   # fills the full 200 px width
        sb.grid_rowconfigure(8, weight=1)       # pushes version label to bottom

        ctk.CTkLabel(sb, text="[ SNM ]", font=("Courier New", 16, "bold"),
                     text_color=CYAN).grid(row=0, column=0, padx=20, pady=(24, 2), sticky="w")
        ctk.CTkLabel(sb, text="Network Scanner", font=("Segoe UI", 10),
                     text_color=GRAY).grid(row=1, column=0, padx=20, pady=(0, 10), sticky="w")

        sep = ctk.CTkFrame(sb, height=1, fg_color=BORDER)
        sep.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 10))

        for i, page in enumerate(PAGES):
            btn_frame = ctk.CTkFrame(sb, fg_color="transparent", height=48)
            btn_frame.grid(row=3 + i, column=0, sticky="ew", pady=1)
            btn_frame.pack_propagate(False)

            accent = ctk.CTkFrame(btn_frame, width=3, fg_color="transparent", corner_radius=0)
            accent.pack(side="left", fill="y")
            self.nav_accents[page] = accent

            btn = ctk.CTkButton(
                btn_frame,
                text=f"   {PAGE_ICONS[page]}   {page}",
                font=("Courier New", 13),
                anchor="w",
                fg_color="transparent",
                hover_color="#0d2137",
                text_color=GRAY,
                corner_radius=0,
                command=lambda p=page: self._show_page(p),
            )
            btn.pack(side="left", fill="both", expand=True)
            self.nav_buttons[page] = btn

        ctk.CTkLabel(sb, text="v1.0 | Python", font=("Segoe UI", 9),
                     text_color=GRAY).grid(row=8, column=0, padx=20, pady=16, sticky="sw")

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
        self.active_page = name
        for page, btn in self.nav_buttons.items():
            if page == name:
                btn.configure(text_color=CYAN, fg_color="#0d2137")
                self.nav_accents[page].configure(fg_color=CYAN)
            else:
                btn.configure(text_color=GRAY, fg_color="transparent")
                self.nav_accents[page].configure(fg_color="transparent")
        self.pages[name].tkraise()
        if name == "DASHBOARD":
            self._refresh_dashboard()
        if name == "RESULTS":
            self._populate_results_page()

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
        frame = ctk.CTkFrame(self.content, fg_color=BG_MAIN, corner_radius=0)

        ctk.CTkLabel(frame, text="[ DASHBOARD ]", font=("Courier New", 18, "bold"),
                     text_color=CYAN).pack(anchor="w", padx=24, pady=(24, 14))

        # Stat cards
        cards_row = ctk.CTkFrame(frame, fg_color="transparent")
        cards_row.pack(fill="x", padx=24, pady=(0, 12))
        for i in range(4):
            cards_row.grid_columnconfigure(i, weight=1)

        card_defs = [
            ("HOSTS SCANNED", "stat_hosts", WHITE),
            ("OPEN PORTS",    "stat_ports", WHITE),
            ("VULNERABLE",    "stat_vuln",  RED),
            ("LAST SCAN",     "stat_date",  WHITE),
        ]
        for col, (label, attr, color) in enumerate(card_defs):
            card = ctk.CTkFrame(cards_row, fg_color=BG_SIDE,
                                border_color=BORDER, border_width=1, corner_radius=8)
            card.grid(row=0, column=col, padx=5, sticky="ew")
            ctk.CTkLabel(card, text=label, font=("Segoe UI", 10),
                         text_color=GRAY).pack(anchor="w", padx=14, pady=(12, 2))
            lbl = ctk.CTkLabel(card, text="—", font=("Courier New", 22, "bold"),
                               text_color=color)
            lbl.pack(anchor="w", padx=14, pady=(0, 12))
            setattr(self, attr, lbl)

        bar = ctk.CTkFrame(frame, fg_color="transparent")
        bar.pack(fill="x", padx=24, pady=(0, 6))
        ctk.CTkButton(bar, text="[ REFRESH ]", font=("Courier New", 11),
                      fg_color=BORDER, text_color=CYAN, hover_color=BG_SIDE,
                      width=110, command=self._refresh_dashboard).pack(side="right")

        self.dash_scroll = ctk.CTkScrollableFrame(frame, fg_color=BG_SIDE,
                                                   border_color=BORDER, border_width=1,
                                                   corner_radius=8)
        self.dash_scroll.pack(fill="both", expand=True, padx=24, pady=(0, 24))

        return frame

    def _refresh_dashboard(self):
        for w in self.dash_scroll.winfo_children():
            w.destroy()

        if not os.path.exists(SCAN_RESULT_PATH):
            self._dash_reset_stats()
            ctk.CTkLabel(self.dash_scroll,
                         text="No scan data found. Start a new scan.",
                         font=("Segoe UI", 12), text_color=GRAY).pack(expand=True, pady=50)
            return

        try:
            with open(SCAN_RESULT_PATH, "r", encoding="utf-8") as f:
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

    # ════════════════════════════════════════════════════════════
    #  PAGE 2 — NEW SCAN
    # ════════════════════════════════════════════════════════════

    def _build_new_scan(self):
        outer = ctk.CTkFrame(self.content, fg_color=BG_MAIN, corner_radius=0)
        ctk.CTkLabel(outer, text="[ NEW SCAN ]", font=("Courier New", 18, "bold"),
                     text_color=CYAN).pack(anchor="w", padx=24, pady=(24, 14))

        self._scan_scroll = ctk.CTkScrollableFrame(outer, fg_color=BG_MAIN)
        self._scan_scroll.pack(fill="both", expand=True)

        self._build_step1(self._scan_scroll)
        self._build_step2(self._scan_scroll)
        self._build_step3(self._scan_scroll)

        return outer

    # ── Step 1 — Network Configuration ──────────────────────────

    def _build_step1(self, parent):
        box = ctk.CTkFrame(parent, fg_color=BG_SIDE, border_color=BORDER,
                            border_width=1, corner_radius=8)
        box.pack(fill="x", padx=24, pady=(0, 10))

        ctk.CTkLabel(box, text="STEP 1 — NETWORK CONFIGURATION",
                     font=("Segoe UI", 11), text_color=GRAY).pack(anchor="w", padx=16, pady=(12, 8))

        row = ctk.CTkFrame(box, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(0, 8))

        ctk.CTkLabel(row, text="NETWORK CIDR:", font=("Courier New", 11),
                     text_color=GRAY).pack(side="left", padx=(0, 8))
        ctk.CTkEntry(row, width=200, placeholder_text="192.168.1.0/24",
                     textvariable=self.cidr_var,
                     font=("Courier New", 11)).pack(side="left", padx=(0, 8))
        ctk.CTkButton(row, text="[ AUTO DETECT ]", font=("Courier New", 11),
                      fg_color=BORDER, text_color=CYAN, hover_color=BG_MAIN,
                      command=self._auto_detect_cidr).pack(side="left", padx=(0, 8))
        ctk.CTkButton(row, text="[ DISCOVER HOSTS ]", font=("Courier New", 11, "bold"),
                      fg_color=CYAN, text_color=BG_MAIN, hover_color="#00d4db",
                      command=self._start_host_discovery).pack(side="left")

        self.discovery_status = ctk.CTkLabel(box, text="", font=("Courier New", 10),
                                              text_color=CYAN)
        self.discovery_status.pack(anchor="w", padx=16, pady=(0, 4))

        self.hosts_table_frame = ctk.CTkScrollableFrame(box, fg_color=BG_MAIN,
                                                         height=180, corner_radius=6)
        self.hosts_table_frame.pack(fill="x", padx=16, pady=(0, 12))

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
        self.discovery_status.configure(text="Discovering hosts...")
        for w in self.hosts_table_frame.winfo_children():
            w.destroy()
        threading.Thread(target=self._run_host_discovery, args=(cidr,), daemon=True).start()

    def _run_host_discovery(self, cidr):
        try:
            hosts = scan_subnet(cidr)
            alive = [h for h in hosts if h.get("alive")]
        except Exception as e:
            self.after(0, lambda msg=str(e): self.discovery_status.configure(
                text=f"Error: {msg}"))
            return
        self.discovered_hosts = alive
        self.after(0, self._on_hosts_discovered)

    def _on_hosts_discovered(self):
        hosts = self.discovered_hosts
        self.discovery_status.configure(
            text=f"Found {len(hosts)} alive host(s)." if hosts else "No alive hosts found.")

        for w in self.hosts_table_frame.winfo_children():
            w.destroy()

        if not hosts:
            ctk.CTkLabel(self.hosts_table_frame, text="No hosts responded on this network.",
                         text_color=GRAY, font=("Segoe UI", 11)).pack(pady=20)
            return

        cols   = ["IP", "HOSTNAME", "MAC", "LATENCY", "ACTION"]
        widths = [120, 200, 160, 80, 100]

        hdr = ctk.CTkFrame(self.hosts_table_frame, fg_color=BG_SIDE)
        hdr.pack(fill="x", pady=(0, 2))
        for c, w in zip(cols, widths):
            ctk.CTkLabel(hdr, text=c, font=("Courier New", 10),
                         text_color=GRAY, width=w, anchor="w").pack(side="left", padx=4)

        for h in hosts:
            ip  = h.get("ip", "")
            hn  = h.get("hostname") or "—"
            mac = h.get("mac") or "—"
            lat = f"{h.get('latency', 0):.1f}ms" if h.get("latency") else "—"

            row = ctk.CTkFrame(self.hosts_table_frame, fg_color=BG_MAIN, corner_radius=4)
            row.pack(fill="x", pady=1)
            for val, w in zip([ip, hn, mac, lat], widths[:-1]):
                ctk.CTkLabel(row, text=val, font=("Courier New", 10),
                             text_color=WHITE, width=w, anchor="w").pack(side="left", padx=4, pady=3)
            ctk.CTkButton(row, text="[ SELECT ]", font=("Courier New", 10),
                          fg_color=BORDER, text_color=CYAN, hover_color=BG_SIDE,
                          width=90,
                          command=lambda _ip=ip: self._select_host(_ip)).pack(side="left", padx=4)

    # ── Step 2 — Scan Configuration ─────────────────────────────

    def _build_step2(self, parent):
        self.step2_frame = ctk.CTkFrame(parent, fg_color=BG_SIDE, border_color=BORDER,
                                         border_width=1, corner_radius=8)
        # Packed lazily by _select_host

        ctk.CTkLabel(self.step2_frame, text="STEP 2 — SCAN CONFIGURATION",
                     font=("Segoe UI", 11), text_color=GRAY).pack(anchor="w", padx=16, pady=(12, 8))

        self.target_label = ctk.CTkLabel(self.step2_frame, text="TARGET: —",
                                          font=("Courier New", 13, "bold"), text_color=CYAN)
        self.target_label.pack(anchor="w", padx=16, pady=(0, 10))

        self.scan_mode_btn = ctk.CTkSegmentedButton(
            self.step2_frame,
            values=["FAST", "FULL", "CUSTOM"],
            variable=self.scan_mode_var,
            font=("Courier New", 11),
            command=self._on_scan_mode_change,
        )
        self.scan_mode_btn.pack(anchor="w", padx=16, pady=(0, 8))

        # Wrapper always sits between the segment button and LAUNCH button.
        # When CUSTOM is selected the entry is packed inside; otherwise empty
        # and the frame collapses to zero height automatically.
        self._custom_wrap = ctk.CTkFrame(self.step2_frame, fg_color="transparent")
        self._custom_wrap.pack(fill="x", padx=16)

        self.custom_ports_entry = ctk.CTkEntry(
            self._custom_wrap,
            placeholder_text="e.g. 80,443,8080",
            textvariable=self.custom_ports_var,
            font=("Courier New", 11),
            width=300,
        )
        # Not packed yet — shown by _on_scan_mode_change

        self.launch_btn = ctk.CTkButton(
            self.step2_frame,
            text="[ LAUNCH SCAN ]",
            font=("Courier New", 12, "bold"),
            fg_color=RED,
            hover_color="#cc0033",
            text_color=WHITE,
            width=200,
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
            ports = [int(p.strip()) for p in raw.split(",") if p.strip().isdigit()]
            return ports if ports else list(FAST_PORTS)
        except Exception:
            return list(FAST_PORTS)

    # ── Step 3 — Progress & Live Log ────────────────────────────

    def _build_step3(self, parent):
        self.step3_frame = ctk.CTkFrame(parent, fg_color=BG_SIDE, border_color=BORDER,
                                         border_width=1, corner_radius=8)
        # Packed lazily by _launch_scan

        self.scanning_label = ctk.CTkLabel(self.step3_frame, text="",
                                            font=("Courier New", 12, "bold"), text_color=CYAN)
        self.scanning_label.pack(anchor="w", padx=16, pady=(12, 4))

        self.progress_bar = ctk.CTkProgressBar(self.step3_frame, mode="indeterminate",
                                                progress_color=CYAN, fg_color=BORDER)
        self.progress_bar.pack(fill="x", padx=16, pady=(0, 8))

        self.log_frame = ctk.CTkScrollableFrame(self.step3_frame, fg_color="#050810",
                                                 height=220, corner_radius=6)
        self.log_frame.pack(fill="x", padx=16, pady=(0, 8))

        self.view_results_btn = ctk.CTkButton(
            self.step3_frame,
            text="[ VIEW RESULTS ]",
            font=("Courier New", 11, "bold"),
            fg_color=CYAN,
            text_color=BG_MAIN,
            hover_color="#00d4db",
            command=lambda: self._show_page("RESULTS"),
        )
        # Packed by _on_scan_complete

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

        # Show step 3 on first launch
        if not self._step3_shown:
            self.step3_frame.pack(fill="x", padx=24, pady=(0, 10))
            self._step3_shown = True

        # Reset UI for this run
        self.view_results_btn.pack_forget()
        for w in self.log_frame.winfo_children():
            w.destroy()

        # Disable button to prevent re-entry
        self._scanning = True
        self.launch_btn.configure(state="disabled", text="[ SCANNING... ]")

        self.scan_results  = []
        self.scan_start_t  = time.time()
        self.scan_duration = 0.0

        # Start progress bar (indeterminate until first result)
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
                        r["confidence"] = round(pred["confidence"] * 100, 2)
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
                       f" → VULNÉRABLE ({conf:.1f}%)")
            else:
                color = GREEN
                txt = (f"[OPEN]   port {port:<6} {svc:<10} {ver:<18}"
                       f" → SAFE ({conf:.1f}%)")
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
        os.makedirs(OUTPUTS_DIR, exist_ok=True)
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
        with open(SCAN_RESULT_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    # ════════════════════════════════════════════════════════════
    #  PAGE 3 — RESULTS
    # ════════════════════════════════════════════════════════════

    def _build_results(self):
        frame = ctk.CTkFrame(self.content, fg_color=BG_MAIN, corner_radius=0)

        ctk.CTkLabel(frame, text="[ SCAN RESULTS ]", font=("Courier New", 18, "bold"),
                     text_color=CYAN).pack(anchor="w", padx=24, pady=(24, 12))

        # Info bar
        info = ctk.CTkFrame(frame, fg_color=BG_SIDE, border_color=BORDER,
                             border_width=1, corner_radius=8)
        info.pack(fill="x", padx=24, pady=(0, 8))
        self.res_target = ctk.CTkLabel(info, text="TARGET: —",
                                        font=("Courier New", 11, "bold"), text_color=CYAN)
        self.res_target.pack(side="left", padx=16, pady=10)
        self.res_date = ctk.CTkLabel(info, text="DATE: —",
                                      font=("Courier New", 11), text_color=GRAY)
        self.res_date.pack(side="left", padx=12)
        self.res_dur = ctk.CTkLabel(info, text="DURATION: —",
                                     font=("Courier New", 11), text_color=GRAY)
        self.res_dur.pack(side="left", padx=12)

        # Badges
        badges = ctk.CTkFrame(frame, fg_color="transparent")
        badges.pack(fill="x", padx=24, pady=(0, 8))
        self.badge_total = self._make_badge(badges, "TOTAL SCANNED", "—", WHITE)
        self.badge_open  = self._make_badge(badges, "OPEN PORTS",    "—", CYAN)
        self.badge_vuln  = self._make_badge(badges, "VULNERABLE",    "—", RED)
        self.badge_safe  = self._make_badge(badges, "SAFE",          "—", GREEN)

        # Table — header stays fixed, only rows scroll
        table_wrap = ctk.CTkFrame(frame, fg_color=BG_SIDE,
                                   border_color=BORDER, border_width=1, corner_radius=8)
        table_wrap.pack(fill="both", expand=True, padx=24, pady=(0, 8))

        self.res_header = ctk.CTkFrame(table_wrap, fg_color=BG_SIDE, corner_radius=0)
        self.res_header.pack(fill="x")

        self.res_table = ctk.CTkScrollableFrame(table_wrap, fg_color="transparent",
                                                 corner_radius=0)
        self.res_table.pack(fill="both", expand=True)

        # Bottom buttons
        btns = ctk.CTkFrame(frame, fg_color="transparent")
        btns.pack(fill="x", padx=24, pady=(0, 16))
        ctk.CTkButton(btns, text="[ EXPORT JSON ]", font=("Courier New", 11),
                      fg_color=BORDER, text_color=CYAN, hover_color=BG_SIDE,
                      command=self._export_json).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btns, text="[ NEW SCAN ]", font=("Courier New", 11),
                      fg_color=BORDER, text_color=CYAN, hover_color=BG_SIDE,
                      command=lambda: self._show_page("NEW SCAN")).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btns, text="[ DASHBOARD ]", font=("Courier New", 11),
                      fg_color=BORDER, text_color=CYAN, hover_color=BG_SIDE,
                      command=lambda: self._show_page("DASHBOARD")).pack(side="left")

        return frame

    def _make_badge(self, parent, label, val, color):
        f = ctk.CTkFrame(parent, fg_color=BG_SIDE, border_color=BORDER,
                          border_width=1, corner_radius=8)
        f.pack(side="left", padx=(0, 8))
        ctk.CTkLabel(f, text=label, font=("Segoe UI", 9),
                     text_color=GRAY).pack(padx=14, pady=(8, 0))
        lbl = ctk.CTkLabel(f, text=val, font=("Courier New", 16, "bold"), text_color=color)
        lbl.pack(padx=14, pady=(0, 8))
        return lbl

    def _populate_results_page(self):
        for w in self.res_table.winfo_children():
            w.destroy()

        if self.scan_results:
            # Use live in-memory results (scan just completed)
            ports = [
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
                for r in self.scan_results
            ]
            self.res_target.configure(text=f"TARGET: {self.selected_ip or '—'}")
            self.res_date.configure(
                text=f"DATE: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            self.res_dur.configure(text=f"DURATION: {self.scan_duration}s")

        elif os.path.exists(SCAN_RESULT_PATH):
            # Fall back to saved JSON
            try:
                with open(SCAN_RESULT_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                ports = data.get("ports", [])
                self.res_target.configure(text=f"TARGET: {data.get('cible', '—')}")
                self.res_date.configure(text=f"DATE: {data.get('date', '—')}")
                dur = data.get("duration_seconds", "—")
                self.res_dur.configure(text=f"DURATION: {dur}s")
            except Exception:
                ports = []
        else:
            ports = []
            self.res_target.configure(text="TARGET: —")
            self.res_date.configure(text="DATE: —")
            self.res_dur.configure(text="DURATION: —")

        open_p = [p for p in ports if p.get("statut") == "ouvert"]
        vuln_p = [p for p in open_p if p.get("vulnerable") == 1]
        safe_p = [p for p in open_p if p.get("vulnerable") == 0]

        self.badge_total.configure(text=str(len(ports)))
        self.badge_open.configure(text=str(len(open_p)))
        self.badge_vuln.configure(text=str(len(vuln_p)))
        self.badge_safe.configure(text=str(len(safe_p)))

        # ── Clear and rebuild sticky header ──────────────────────
        for w in self.res_header.winfo_children():
            w.destroy()

        if not ports:
            ctk.CTkLabel(self.res_table, text="No results available.",
                         font=("Segoe UI", 12), text_color=GRAY).pack(pady=40)
            return

        cols   = ["PORT", "PROTO", "STATUS", "SERVICE", "VERSION", "AI LABEL", "CONFIDENCE"]
        widths = [65, 60, 110, 110, 180, 130, 90]

        # Header row — sits outside the scroll area, always visible
        sep_top = ctk.CTkFrame(self.res_header, height=1, fg_color=BORDER)
        sep_top.pack(fill="x")
        hdr_row = ctk.CTkFrame(self.res_header, fg_color=BG_SIDE, corner_radius=0)
        hdr_row.pack(fill="x")
        for c, w in zip(cols, widths):
            ctk.CTkLabel(hdr_row, text=c, font=("Courier New", 10),
                         text_color=GRAY, width=w, anchor="w").pack(side="left", padx=6, pady=4)
        sep_bot = ctk.CTkFrame(self.res_header, height=1, fg_color=BORDER)
        sep_bot.pack(fill="x")

        # ── Data rows ────────────────────────────────────────────
        for i, p in enumerate(ports):
            row_bg  = BG_SIDE if i % 2 == 0 else BG_MAIN
            is_vuln = p.get("vulnerable") == 1
            statut  = p.get("statut", "")
            label   = p.get("label", "—")
            conf    = p.get("confidence", 0.0)

            # Row text colour driven by status
            if statut == "ouvert":
                base_col = RED if is_vuln else CYAN
            elif "filtré" in statut or "timeout" in statut:
                base_col = GRAY
            else:
                base_col = "#2d3748"   # dimmed for fermé / erreur

            label_col  = RED if is_vuln else (GREEN if statut == "ouvert" else GRAY)
            label_font = ("Courier New", 10, "bold") if is_vuln else ("Courier New", 10)
            conf_col   = RED if is_vuln else (GREEN if statut == "ouvert" else GRAY)

            row = ctk.CTkFrame(self.res_table, fg_color=row_bg, corner_radius=0)
            row.pack(fill="x")

            row_vals = [
                str(p.get("port", "")),
                p.get("protocole", "TCP"),
                statut,
                p.get("service", ""),
                p.get("version", ""),
            ]
            for val, w in zip(row_vals, widths[:5]):
                ctk.CTkLabel(row, text=val, font=("Courier New", 10),
                             text_color=base_col, width=w, anchor="w").pack(
                                 side="left", padx=6, pady=1)

            ctk.CTkLabel(row, text=label, font=label_font, text_color=label_col,
                         width=widths[5], anchor="w").pack(side="left", padx=6, pady=1)

            conf_txt = f"{conf:.1f}%" if conf > 0 else "—"
            ctk.CTkLabel(row, text=conf_txt, font=("Courier New", 10),
                         text_color=conf_col, width=widths[6], anchor="w").pack(
                             side="left", padx=6, pady=1)

    def _export_json(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile="scan_result.json",
        )
        if not path:
            return
        if os.path.exists(SCAN_RESULT_PATH):
            with open(SCAN_RESULT_PATH, "r", encoding="utf-8") as f:
                data = f.read()
            with open(path, "w", encoding="utf-8") as f:
                f.write(data)
            messagebox.showinfo("Export", f"Saved to:\n{path}")
        else:
            messagebox.showwarning("Export", "No scan data to export.")

    # ════════════════════════════════════════════════════════════
    #  PAGE 4 — ABOUT
    # ════════════════════════════════════════════════════════════

    def _build_about(self):
        frame = ctk.CTkFrame(self.content, fg_color=BG_MAIN, corner_radius=0)

        inner = ctk.CTkFrame(frame, fg_color="transparent")
        inner.place(relx=0.5, rely=0.5, anchor="center")

        ascii_art = (
            "███████╗███╗   ██╗███╗   ███╗\n"
            "██╔════╝████╗  ██║████╗ ████║\n"
            "███████╗██╔██╗ ██║██╔████╔██║\n"
            "╚════██║██║╚██╗██║██║╚██╔╝██║\n"
            "███████║██║ ╚████║██║ ╚═╝ ██║\n"
            "╚══════╝╚═╝  ╚═══╝╚═╝     ╚═╝"
        )
        ctk.CTkLabel(inner, text=ascii_art, font=("Courier New", 11),
                     text_color=CYAN, justify="center").pack(pady=(0, 14))

        ctk.CTkLabel(inner, text="Smart Network Mapper",
                     font=("Segoe UI", 14, "bold"), text_color=WHITE).pack()
        ctk.CTkLabel(inner, text="AI-Powered Vulnerability Scanner",
                     font=("Segoe UI", 11), text_color=GRAY).pack(pady=(2, 18))

        for key, val in [("Version", "1.0.0"), ("Author", "Amine Nahli"), ("License", "MIT")]:
            r = ctk.CTkFrame(inner, fg_color="transparent")
            r.pack(pady=3)
            ctk.CTkLabel(r, text=f"{key}:", font=("Courier New", 11),
                         text_color=GRAY, width=80, anchor="e").pack(side="left")
            ctk.CTkLabel(r, text=val, font=("Courier New", 11),
                         text_color=WHITE).pack(side="left", padx=10)

        ctk.CTkLabel(inner, text="\nTech Stack",
                     font=("Segoe UI", 10, "bold"), text_color=GRAY).pack()
        ctk.CTkLabel(
            inner,
            text="Python  |  CustomTkinter  |  Scapy  |  RandomForest  |  Threading",
            font=("Courier New", 10),
            text_color=CYAN,
        ).pack()

        return frame


# ════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = SmartNetworkMapper()
    app.mainloop()
