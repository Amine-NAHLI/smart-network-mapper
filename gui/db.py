"""
gui/db.py
---------
Gestionnaire de base de données SQLite pour l'historique des scans.

La base est stockée localement dans le dossier outputs/ de l'application
(à côté des rapports HTML et JSON). Chaque utilisateur possède son propre
historique, sans besoin de serveur distant.
"""

import os
import sqlite3
from datetime import datetime

from snm_paths import get_outputs_dir, ensure_outputs_dir


def _db_path() -> str:
    """Retourne le chemin vers la base SQLite (outputs/history.db)."""
    ensure_outputs_dir()
    return os.path.join(get_outputs_dir(), "history.db")


def _connect():
    """Ouvre une connexion et active le mode WAL pour la concurrence."""
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Crée la table `scans` si elle n'existe pas encore."""
    conn = _connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target      TEXT    NOT NULL,
            date        TEXT    NOT NULL,
            duration    REAL    DEFAULT 0,
            open_ports  INTEGER DEFAULT 0,
            vuln_ports  INTEGER DEFAULT 0,
            total_ports INTEGER DEFAULT 0,
            json_path   TEXT    DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()


def insert_scan(target: str, date: str, duration: float,
                open_ports: int, vuln_ports: int, total_ports: int,
                json_path: str = "") -> int:
    """Insère un résumé de scan et retourne l'id généré."""
    conn = _connect()
    cur = conn.execute(
        """INSERT INTO scans
           (target, date, duration, open_ports, vuln_ports, total_ports, json_path)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (target, date, duration, open_ports, vuln_ports, total_ports, json_path),
    )
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_all_scans() -> list[dict]:
    """Retourne tous les scans, du plus récent au plus ancien."""
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_by_id(scan_id: int) -> dict | None:
    """Retourne un scan par son id, ou None."""
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def delete_scan(scan_id: int):
    """Supprime un scan de l'historique."""
    conn = _connect()
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()


def delete_all_scans():
    """Supprime tout l'historique."""
    conn = _connect()
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
