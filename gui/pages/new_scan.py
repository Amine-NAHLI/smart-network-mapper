"""
gui/pages/new_scan.py
---------------------
Page « NEW SCAN » — configuration et exécution d'un scan réseau.
"""

import threading
import time
import os
import json
import customtkinter as ctk
from tkinter import messagebox
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from gui.constants import *
from scanner.host_discovery import scan_subnet
from scanner.port_scanner import scan_tcp, scan_udp_ports
from scanner.device_info import get_hostname_dns, get_mac_arp
from scanner.utils import detect_lan_config
from model.predictor import predict
from reporter.html_generator import generate_html_report
from core.paths import get_outputs_dir, ensure_outputs_dir
from gui import db


class NewScanPage(ctk.CTkFrame):
    """Page de configuration réseau, découverte d'hôtes, et lancement de scan."""

    def __init__(self, parent, app):
        super().__init__(parent, fg_color=NAVY_BLACK, corner_radius=0)
        self.app = app

        # Scan state
        self.selected_ip      = None
        self.scan_results     = []
        self.scan_start_t     = 0.0
        self.scan_duration    = 0.0
        self.discovered_hosts = []
        self._step2_shown     = False
        self._step3_shown     = False
        self._scanning        = False

        # Blink state
        self._blink_state = True
        self._blink_job   = None

        # Tkinter vars
        self.cidr_var         = ctk.StringVar(value="")
        self.target_ip_var    = ctk.StringVar(value="")
        self.scan_mode_var    = ctk.StringVar(value="FAST")
        self.custom_ports_var = ctk.StringVar(value="")

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
        ctk.CTkLabel(lbl_box, text="NEW SCAN", font=self.app.FONT_MONO_LG, text_color=TEXT_PRIMARY).pack(side="left")
        ctk.CTkLabel(lbl_box, text=" ]", font=self.app.FONT_MONO_LG, text_color=CYAN_ACCENT).pack(side="left")

        self._scan_scroll = ctk.CTkScrollableFrame(self, fg_color=NAVY_BLACK)
        self._scan_scroll.pack(fill="both", expand=True)

        self._build_direct_scan(self._scan_scroll)
        self._build_step1(self._scan_scroll)
        self._build_step2(self._scan_scroll)
        self._build_step3(self._scan_scroll)

    # ── Direct Scan — Single IP / External ──────────────────────

    def _build_direct_scan(self, parent):
        box = ctk.CTkFrame(parent, fg_color=NAVY_SIDEBAR, border_color=BORDER_COLOR,
                            border_width=1, corner_radius=8)
        box.pack(fill="x", padx=24, pady=(20, 10))

        ctk.CTkLabel(box, text="◆  QUICK SCAN — SINGLE TARGET",
                     font=self.app.FONT_MONO_SM, text_color=TEXT_MUTED).pack(anchor="w", padx=16, pady=(12, 4))
        ctk.CTkFrame(box, height=1, fg_color=BORDER_COLOR).pack(fill="x", padx=16, pady=(0, 8))

        row = ctk.CTkFrame(box, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(0, 16))

        ctk.CTkLabel(row, text="TARGET IP:", font=self.app.FONT_MONO_MD,
                     text_color=TEXT_SECONDARY).pack(side="left", padx=(0, 12))
        ctk.CTkEntry(row, width=280, placeholder_text="e.g. 8.8.8.8 or 192.168.1.1",
                     textvariable=self.target_ip_var,
                     fg_color=NAVY_CARD, border_color=BORDER_COLOR,
                     border_width=1, corner_radius=4,
                     font=self.app.FONT_MONO_MD).pack(side="left", padx=(0, 12))

        ctk.CTkButton(row, text="[ SELECT TARGET ]", font=self.app.FONT_MONO_MD,
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
                     font=self.app.FONT_MONO_SM, text_color=TEXT_MUTED).pack(anchor="w", padx=16, pady=(12, 4))
        ctk.CTkFrame(box, height=1, fg_color=BORDER_COLOR).pack(fill="x", padx=16, pady=(0, 8))

        row = ctk.CTkFrame(box, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(0, 12))

        ctk.CTkLabel(row, text="NETWORK CIDR:", font=self.app.FONT_MONO_MD,
                     text_color=TEXT_SECONDARY).pack(side="left", padx=(0, 12))
        ctk.CTkEntry(row, width=200, placeholder_text="192.168.1.0/24",
                     textvariable=self.cidr_var,
                     fg_color=NAVY_CARD, border_color=BORDER_COLOR,
                     border_width=1, corner_radius=4,
                     font=self.app.FONT_MONO_MD).pack(side="left", padx=(0, 12))
        ctk.CTkButton(row, text="[ AUTO DETECT ]", font=self.app.FONT_MONO_MD,
                      fg_color="transparent", text_color=CYAN_ACCENT, border_color=CYAN_ACCENT,
                      border_width=1, hover_color=NAVY_SIDEBAR, height=36,
                      command=self._auto_detect_cidr).pack(side="left", padx=(0, 12))
        ctk.CTkButton(row, text="[ DISCOVER HOSTS ]", font=self.app.FONT_MONO_MD,
                      fg_color=CYAN_ACCENT, text_color=NAVY_BLACK, hover_color="#0099BB",
                      corner_radius=4, height=36,
                      command=self._start_host_discovery).pack(side="left")

        self.discovery_status = ctk.CTkLabel(box, text="", font=self.app.FONT_MONO_SM,
                                              text_color=CYAN_ACCENT)
        self.discovery_status.pack(anchor="w", padx=16, pady=(0, 4))

        self.discovery_progress = ctk.CTkProgressBar(box, mode="determinate",
                                                      fg_color=BORDER_COLOR,
                                                      progress_color=CYAN_ACCENT,
                                                      corner_radius=2, height=4)
        self.discovery_progress.set(0)

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
        self.discovery_progress.set(0)
        self.discovery_progress.pack(fill="x", padx=16, pady=(0, 8))
        for w in self.hosts_table_frame.winfo_children():
            w.destroy()
        threading.Thread(target=self._run_host_discovery, args=(cidr,), daemon=True).start()

    def _update_discovery_progress(self, current, total):
        pct = current / max(1, total)
        self.after(0, lambda p=pct: self.discovery_progress.set(p))
        self.after(0, lambda c=current, t=total: self.discovery_status.configure(text=f"●  Discovering hosts... ({c}/{t})"))

    def _run_host_discovery(self, cidr):
        try:
            hosts = scan_subnet(cidr, progress_callback=self._update_discovery_progress)
            alive = [h for h in hosts if h.get("alive")]
        except Exception as e:
            self.after(0, lambda msg=str(e): self.discovery_status.configure(
                text=f"●  Error: {msg}", text_color=RED_DANGER))
            return
        self.discovered_hosts = alive
        self.after(0, self._on_hosts_discovered)

    def _on_hosts_discovered(self):
        hosts = self.discovered_hosts
        self.discovery_progress.pack_forget()
        self.discovery_status.configure(
            text=f"●  Found {len(hosts)} alive host(s)." if hosts else "●  No alive hosts found.",
            text_color=GREEN_SUCCESS if hosts else AMBER_WARNING)

        for w in self.hosts_table_frame.winfo_children():
            w.destroy()

        if not hosts:
            ctk.CTkLabel(self.hosts_table_frame, text="No hosts responded on this network.",
                         text_color=TEXT_MUTED, font=self.app.FONT_MONO_MD).pack(pady=20)
            return

        cols   = ["IP ADDRESS", "HOSTNAME", "MAC ADDRESS", "LATENCY", "ACTION"]
        widths = [140, 200, 160, 80, 100]

        hdr = ctk.CTkFrame(self.hosts_table_frame, fg_color=NAVY_SIDEBAR)
        hdr.pack(fill="x", pady=(0, 2))
        for c, w in zip(cols, widths):
            ctk.CTkLabel(hdr, text=c, font=self.app.FONT_MONO_SM,
                         text_color=TEXT_MUTED, width=w, anchor="w").pack(side="left", padx=4)

        for h in hosts:
            ip  = h.get("ip", "")
            hn  = h.get("hostname") or "—"
            mac = h.get("mac") or "—"
            lat = f"{h.get('latency', 0):.1f}ms" if h.get("latency") else "—"

            row = ctk.CTkFrame(self.hosts_table_frame, fg_color=NAVY_CARD, corner_radius=4)
            row.pack(fill="x", pady=1)

            ctk.CTkLabel(row, text="●", text_color=GREEN_SUCCESS, font=self.app.FONT_MONO_SM).pack(side="left", padx=(8, 0))

            for val, w in zip([ip, hn, mac, lat], [130, 200, 160, 80]):
                ctk.CTkLabel(row, text=val, font=self.app.FONT_MONO_SM,
                             text_color=TEXT_PRIMARY, width=w, anchor="w").pack(side="left", padx=4, pady=3)

            ctk.CTkButton(row, text="[ SELECT ]", font=self.app.FONT_MONO_SM,
                          fg_color="transparent", text_color=CYAN_ACCENT, border_color=CYAN_ACCENT,
                          border_width=1, hover_color=NAVY_SIDEBAR, width=90, height=28,
                          command=lambda _ip=ip: self._select_host(_ip)).pack(side="right", padx=8)

    # ── Step 2 — Scan Configuration ─────────────────────────────

    def _build_step2(self, parent):
        self.step2_frame = ctk.CTkFrame(parent, fg_color=NAVY_SIDEBAR, border_color=BORDER_COLOR,
                                         border_width=1, corner_radius=8)

        ctk.CTkLabel(self.step2_frame, text="◆  STEP 2 — SCAN CONFIGURATION",
                     font=self.app.FONT_MONO_SM, text_color=TEXT_MUTED).pack(anchor="w", padx=16, pady=(12, 4))
        ctk.CTkFrame(self.step2_frame, height=1, fg_color=BORDER_COLOR).pack(fill="x", padx=16, pady=(0, 8))

        self.target_label = ctk.CTkLabel(self.step2_frame, text="TARGET: —",
                                          font=self.app.FONT_MONO_LG, text_color=CYAN_ACCENT)
        self.target_label.pack(anchor="w", padx=16, pady=(0, 10))

        self.scan_mode_btn = ctk.CTkSegmentedButton(
            self.step2_frame,
            values=["FAST", "FULL", "CUSTOM"],
            variable=self.scan_mode_var,
            font=self.app.FONT_MONO_MD,
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
            font=self.app.FONT_MONO_MD,
            width=300,
        )

        self.launch_btn = ctk.CTkButton(
            self.step2_frame,
            text="[ LAUNCH SCAN ]",
            font=self.app.FONT_MONO_MD,
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
                if not part:
                    continue
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
                                            font=self.app.FONT_MONO_LG, text_color=CYAN_ACCENT)
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
            font=self.app.FONT_MONO_MD,
            fg_color=CYAN_ACCENT,
            text_color=NAVY_BLACK,
            hover_color="#0099BB",
            corner_radius=4, height=36,
            command=lambda: self.app.show_page("RESULTS"),
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

                self.after(0, lambda p=pct: self._update_progress(p))
                self.after(0, lambda entry=dict(r): self._append_log(entry))

        # Scan UDP sur les ports critiques (DNS, SNMP, DHCP, NTP…)
        udp_results = scan_udp_ports(ip)
        for r in udp_results:
            if r.get("statut") == "ouvert":
                try:
                    pred = predict(
                        port=r["port"],
                        version_string=r.get("version", ""),
                        service=r.get("service", ""),
                        protocol="udp",
                    )
                    r["vulnerable"] = pred["vulnerable"]
                    r["confidence"] = pred["confidence"]
                    r["label"] = pred["label"]
                except Exception:
                    r["vulnerable"] = 0
                    r["confidence"] = 0.0
                    r["label"] = "—"
                enriched.append(r)
                self.after(0, lambda entry=dict(r): self._append_log(entry))

        self.scan_results = sorted(
            enriched,
            key=lambda x: (x.get("protocole", "TCP"), x.get("port", 0)),
        )
        self.after(0, self._on_scan_complete)

    def _update_progress(self, pct):
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

        proto = r.get("protocole", "TCP")
        if statut == "ouvert":
            conf_pct = conf * 100 if conf <= 1 else conf
            if r.get("vulnerable") == 1:
                color = RED
                txt = (f"[OPEN/{proto}] port {port:<6} {svc:<10} {ver:<18}"
                       f" → VULNÉRABLE ({conf_pct:.1f}%)")
            else:
                color = GREEN
                txt = (f"[OPEN/{proto}] port {port:<6} {svc:<10} {ver:<18}"
                       f" → SAFE ({conf_pct:.1f}%)")
        else:
            color = GRAY
            txt   = f"[{statut.upper():<7}/{proto}] port {port:<6} {svc:<10}"

        ctk.CTkLabel(self.log_frame, text=txt, font=("Courier New", 10),
                     text_color=color, anchor="w").pack(fill="x", padx=4, pady=1)

    def _on_scan_complete(self):
        self._scanning = False
        self._stop_blink()
        self.progress_bar.stop()
        self.progress_bar.set(1.0)

        self.scan_duration = round(time.time() - self.scan_start_t, 1)

        # Sauvegarder le résultat JSON
        json_path = self._save_result(self.selected_ip, self.scan_results, self.scan_duration)

        # Enregistrer dans l'historique SQLite
        open_ports = [r for r in self.scan_results if r.get("statut") == "ouvert"]
        vuln_ports = [r for r in open_ports if r.get("vulnerable") == 1]
        db.insert_scan(
            target=self.selected_ip,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            duration=self.scan_duration,
            open_ports=len(open_ports),
            vuln_ports=len(vuln_ports),
            total_ports=len(self.scan_results),
            json_path=json_path,
            source="GUI",
            raw_data=json.dumps(self.scan_results, ensure_ascii=False)
        )

        # Propager les résultats au contexte partagé de l'app
        self.app.shared_scan_results   = self.scan_results
        self.app.shared_selected_ip    = self.selected_ip
        self.app.shared_scan_duration  = self.scan_duration

        self.launch_btn.configure(state="normal", text="[ LAUNCH SCAN ]", fg_color=CYAN_ACCENT)
        self.view_results_btn.pack(pady=(4, 16))

        # Auto-refresh dashboard
        self.app.pages["DASHBOARD"].refresh()

    def _save_result(self, ip, results, duration) -> str:
        ensure_outputs_dir()
        outputs_dir = get_outputs_dir()
        open_only = [r for r in results if r.get("statut") == "ouvert"]
        data = {
            "cible":            ip,
            "date":             datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source":           "GUI",
            "duration_seconds": duration,
            "total_scanned":    len(results),
            "ports": [
                {
                    "port":       r.get("port"),
                    "protocole":  r.get("protocole", "TCP"),
                    "statut":     r.get("statut"),
                    "service":    r.get("service", ""),
                    "version":    r.get("version", ""),
                    "vulnerable": r.get("vulnerable", 0),
                    "confidence": r.get("confidence", 0.0),
                    "label":      r.get("label", "—"),
                }
                for r in open_only
            ],
        }

        json_path = os.path.join(outputs_dir, "scan_result.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        # Génération automatique du rapport HTML Premium
        try:
            report_path = os.path.join(outputs_dir, "report.html")
            generate_html_report(data, report_path)
        except Exception:
            pass

        return json_path
