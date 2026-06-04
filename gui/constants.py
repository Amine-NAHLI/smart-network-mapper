"""
gui/constants.py
----------------
Design-system tokens, couleurs, constantes partagées par toute l'interface.
"""

# ── Design System ───────────────────────────────────────────────
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

# ── Legacy aliases ──────────────────────────────────────────────
CYAN    = CYAN_ACCENT
RED     = RED_DANGER
GREEN   = GREEN_SUCCESS
BG_MAIN = NAVY_BLACK
BG_SIDE = NAVY_SIDEBAR
BORDER  = BORDER_COLOR
GRAY    = TEXT_SECONDARY
WHITE   = TEXT_PRIMARY

# ── Port lists ──────────────────────────────────────────────────
FAST_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090,
]

# ── Navigation ──────────────────────────────────────────────────
PAGES      = ["DASHBOARD", "NEW SCAN", "RESULTS", "HISTORY", "ABOUT"]
PAGE_ICONS = {
    "DASHBOARD": "◈",
    "NEW SCAN":  "◉",
    "RESULTS":   "▣",
    "HISTORY":   "◷",
    "ABOUT":     "◎",
}
