"""
gui/pages/about.py
------------------
Page « ABOUT » — informations sur le projet, avec animations canvas cyberpunk.
"""

import tkinter as tk
import customtkinter as ctk

from gui.constants import *


class AboutPage(ctk.CTkFrame):
    """Page d'information avec canvas animé 3D et badges technologiques."""

    def __init__(self, parent, app):
        super().__init__(parent, fg_color=NAVY_BLACK, corner_radius=0)
        self.app = app

        # Animation state
        self._grid_y        = 0
        self._scan_y        = 0.0
        self._glow_on       = True
        self._bullet_on     = True
        self._grid_job      = None
        self._scan_job      = None
        self._glow_job      = None
        self._bull_job      = None
        self._title_id      = None
        self._canvas_w      = 1
        self._canvas_h      = 260
        self._cv             = None
        self._bullet_labels  = []

        self._build()

    # ── Construction ─────────────────────────────────────────────

    def _build(self):
        # Animated canvas header
        self._cv = tk.Canvas(self, height=260, bg=NAVY_BLACK, highlightthickness=0)
        self._cv.pack(fill="x")
        self._cv.bind("<Configure>", lambda e: self._draw_static(e.width, e.height))

        # Scrollable info section
        scroll = ctk.CTkScrollableFrame(self, fg_color=NAVY_BLACK, corner_radius=0)
        scroll.pack(fill="both", expand=True)

        center = ctk.CTkFrame(scroll, fg_color="transparent")
        center.pack(pady=(20, 0))

        ctk.CTkLabel(center, text="Smart Network Mapper",
                     font=self.app.FONT_TITLE, text_color=TEXT_PRIMARY).pack()
        ctk.CTkLabel(center, text="AI-Powered Vulnerability Scanner",
                     font=self.app.FONT_MONO_MD, text_color=CYAN_ACCENT).pack(pady=(4, 14))

        ctk.CTkFrame(center, height=1, fg_color=BORDER_COLOR).pack(fill="x", padx=60, pady=(0, 20))

        # 3 Info cards
        cards_row = ctk.CTkFrame(center, fg_color="transparent")
        cards_row.pack(pady=(0, 20))
        for label, value in [("VERSION", "1.0.0"),
                              ("AUTHOR",  "Amine Nahli"),
                              ("LICENSE", "MIT / ACADEMIC")]:
            cv = tk.Canvas(cards_row, width=180, height=82,
                           bg=NAVY_BLACK, highlightthickness=0)
            cv.pack(side="left", padx=10)
            cv.create_rectangle(4, 4, 180, 82, fill="#003344", outline="")
            cv.create_rectangle(0, 0, 175, 77, fill=NAVY_SIDEBAR, outline="")
            cv.create_rectangle(1, 1, 174, 76, fill="", outline=CYAN_ACCENT, width=1)
            cv.create_text(87, 26, text=label, fill=TEXT_MUTED,
                           font=("Consolas", 9, "bold"))
            cv.create_text(87, 52, text=value, fill=TEXT_PRIMARY,
                           font=("Consolas", 14, "bold"))

        # Tech badges
        techs   = ["Python 3.13", "CustomTkinter", "Scapy", "Deep Learning", "Threading"]
        pad_x, pad_y, gap = 16, 6, 10
        badge_h = 32
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

        # Feature bullets
        ctk.CTkLabel(center, text="[ CORE CAPABILITIES ]", font=self.app.FONT_MONO_MD,
                     text_color=TEXT_MUTED).pack(anchor="w", padx=80, pady=(0, 12))

        self._bullet_labels = []
        features = [
            "Ultra-fast asynchronous port scanning engine",
            "Deep packet inspection and service finger-printing",
            "AI-powered vulnerability assessment (Random Forest)",
            "Live host discovery and network mapping",
            "Premium HTML report generation and JSON exports",
            "Persistent scan history with SQLite database",
        ]
        for feat in features:
            row = ctk.CTkFrame(center, fg_color="transparent")
            row.pack(anchor="w", padx=80, pady=4)
            bullet = ctk.CTkLabel(row, text="◆", font=("Segoe UI", 14),
                                   text_color=CYAN_ACCENT)
            bullet.pack(side="left", padx=(0, 12))
            ctk.CTkLabel(row, text=feat, font=self.app.FONT_MONO_MD,
                         text_color=TEXT_SECONDARY).pack(side="left")
            self._bullet_labels.append(bullet)

        ctk.CTkFrame(center, height=40, fg_color="transparent").pack()

    # ── Canvas drawing helpers ───────────────────────────────────

    @staticmethod
    def _draw_rounded_rect(canvas, x1, y1, x2, y2, r=8, **kw):
        pts = [x1+r, y1,  x2-r, y1,
               x2,   y1,  x2,   y1+r,
               x2,   y2-r, x2,  y2,
               x2-r, y2,  x1+r, y2,
               x1,   y2,  x1,   y2-r,
               x1,   y1+r, x1,  y1]
        canvas.create_polygon(pts, smooth=True, **kw)

    def _draw_static(self, w, h):
        if w <= 1 or h <= 1:
            return
        self._canvas_w = w
        self._canvas_h = h
        cv = self._cv
        cv.delete("all")

        gs = 40
        for x in range(0, w + gs, gs):
            cv.create_line(x, 0, x, h, fill="#003344", stipple="gray25", tags="grid_v")

        self._redraw_grid_h()

        cx, cy = w // 2, h // 2 - 10
        font = ("Consolas", 84, "bold")
        for offset, color in [(6, "#001122"), (5, "#002233"),
                               (4, "#003344"), (3, "#004455"),
                               (2, "#005566"), (1, "#007788")]:
            cv.create_text(cx + offset, cy + offset, text="SNM",
                           fill=color, font=font, anchor="center")

        glow = CYAN_ACCENT if self._glow_on else "#00AAAA"
        self._title_id = cv.create_text(cx, cy, text="SNM",
                                         fill=glow, font=font,
                                         anchor="center", tags="title_top")

        cv.create_text(cx, cy + 64, text="S M A R T   N E T W O R K   M A P P E R",
                       fill=TEXT_MUTED, font=("Consolas", 14), anchor="center")

        cv.create_line(0, 0, w, 0, fill=CYAN_ACCENT, width=2, tags="scanline")
        self._scan_y = 0.0

    def _redraw_grid_h(self):
        cv = self._cv
        if not cv:
            return
        w, h = self._canvas_w, self._canvas_h
        if w <= 1:
            return
        gs = 40
        cv.delete("grid_h")
        offset = int(self._grid_y) % gs
        y = offset - gs
        while y < h + gs:
            cv.create_line(0, y, w, y, fill="#003344", stipple="gray25", tags="grid_h")
            y += gs

    # ── Animation loops ──────────────────────────────────────────

    def _animate_grid(self):
        if not self._is_active():
            return
        self._grid_y = (self._grid_y + 1) % 40
        self._redraw_grid_h()
        self._grid_job = self.after(50, self._animate_grid)

    def _animate_scanline(self):
        if not self._is_active():
            return
        h = self._canvas_h
        w = self._canvas_w
        self._scan_y += 2.5
        if self._scan_y > h + 5:
            self._scan_y = -5.0
        y = int(self._scan_y)
        try:
            self._cv.coords("scanline", 0, y, w, y)
        except Exception:
            pass
        self._scan_job = self.after(16, self._animate_scanline)

    def _animate_glow(self):
        if not self._is_active():
            return
        self._glow_on = not self._glow_on
        color = CYAN_ACCENT if self._glow_on else "#00AAAA"
        try:
            if self._title_id:
                self._cv.itemconfig(self._title_id, fill=color)
        except Exception:
            pass
        self._glow_job = self.after(750, self._animate_glow)

    def _animate_bullets(self):
        if not self._is_active():
            return
        self._bullet_on = not self._bullet_on
        color = CYAN_ACCENT if self._bullet_on else TEXT_PRIMARY
        for lbl in self._bullet_labels:
            try:
                lbl.configure(text_color=color)
            except Exception:
                pass
        self._bull_job = self.after(1000, self._animate_bullets)

    def _is_active(self):
        return self.app.active_page == "ABOUT"

    # ── Public API ───────────────────────────────────────────────

    def start_anims(self):
        self.stop_anims()
        self._animate_grid()
        self._animate_scanline()
        self._animate_glow()
        self._animate_bullets()

    def stop_anims(self):
        for attr in ("_grid_job", "_scan_job", "_glow_job", "_bull_job"):
            job = getattr(self, attr, None)
            if job:
                try:
                    self.after_cancel(job)
                except Exception:
                    pass
                setattr(self, attr, None)
