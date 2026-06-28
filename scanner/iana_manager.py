"""
scanner/iana_manager.py
-----------------------
Gestionnaire de la base de données de ports IANA.
Télécharge, parse, met en cache et fournit la résolution des services/ports
avec repli statique (fallback) et rafraîchissement automatique tous les 30 jours.
"""

import csv
import io
import json
import os
import ssl
import sys
import time
import urllib.request
from datetime import datetime, timezone

from snm_paths import ensure_resources_dir, get_resources_dir

IANA_CSV_URL = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
CACHE_FILENAME = "iana_ports_cache.json"
CACHE_MAX_AGE_DAYS = 30
CACHE_MAX_AGE_SECONDS = CACHE_MAX_AGE_DAYS * 86400

# ── Dictionnaires statiques de fallback ultime ────────────────────────────────
STATIC_SERVICE_NAMES = {
    (80, "tcp"): "http",
    (443, "tcp"): "https",
    (22, "tcp"): "ssh",
    (21, "tcp"): "ftp",
    (25, "tcp"): "smtp",
    (53, "tcp"): "domain",
    (53, "udp"): "domain",
    (110, "tcp"): "pop3",
    (143, "tcp"): "imap",
    (3306, "tcp"): "mysql",
    (5432, "tcp"): "postgresql",
    (6379, "tcp"): "redis",
    (27017, "tcp"): "mongodb",
    (3389, "tcp"): "ms-wbt-server",
    (445, "tcp"): "microsoft-ds",
    (139, "tcp"): "netbios-ssn",
    (8080, "tcp"): "http-alt",
}

STATIC_SERVICE_KEYWORDS = {
    "ssh": "openssh",
    "http": "apache http",
    "https": "apache http",
    "ftp": "vsftpd",
    "smtp": "postfix",
    "mysql": "mysql",
    "ms-sql": "microsoft sql server",
    "rdp": "remote desktop",
    "smb": "samba",
    "dns": "bind dns",
    "telnet": "telnet",
    "vnc": "vnc",
    "redis": "redis",
    "postgres": "postgresql",
    "mongodb": "mongodb",
    "nginx": "nginx",
    "iis": "microsoft iis",
    "tomcat": "apache tomcat",
    "elastic": "elasticsearch",
}

# Variable globale du cache chargé en mémoire
_iana_cache = None


def get_cache_path() -> str:
    ensure_resources_dir()
    return os.path.join(get_resources_dir(), CACHE_FILENAME)


def download_iana_csv(timeout: int = 15) -> str:
    """Télécharge le fichier CSV officiel IANA."""
    req = urllib.request.Request(
        IANA_CSV_URL,
        headers={
            "User-Agent": "SmartNetworkMapper/1.0 (Cybersecurity Audit Tool)"
        },
    )
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def parse_iana_csv(csv_text: str) -> dict:
    """Parse le contenu CSV d'IANA et extrait les ports, services et descriptions."""
    ports_data = {}
    services_data = {}

    reader = csv.DictReader(io.StringIO(csv_text))
    for row in reader:
        service_name = (row.get("Service Name") or "").strip().lower()
        port_str = (row.get("Port Number") or "").strip()
        protocol = (row.get("Transport Protocol") or "").strip().lower()
        description = (row.get("Description") or "").strip()

        if not port_str or not protocol or not port_str.isdigit():
            continue

        port_num = int(port_str)
        key = f"{port_num}/{protocol}"

        if service_name:
            ports_data[key] = {
                "service": service_name,
                "description": description,
            }
            if service_name not in services_data:
                services_data[service_name] = []
            if port_num not in services_data[service_name]:
                services_data[service_name].append(port_num)

    now_ts = int(time.time())
    now_iso = datetime.now(timezone.utc).isoformat()

    return {
        "metadata": {
            "last_updated": now_iso,
            "timestamp": now_ts,
            "total_entries": len(ports_data),
        },
        "ports": ports_data,
        "services": services_data,
    }


def save_iana_cache(cache_data: dict, filepath: str | None = None) -> str:
    if filepath is None:
        filepath = get_cache_path()
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(cache_data, f, indent=2, ensure_ascii=False)
    return filepath


def load_iana_cache(filepath: str | None = None) -> dict | None:
    if filepath is None:
        filepath = get_cache_path()
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def init_iana_database(force_download: bool = False) -> dict:
    """
    Initialise la base de données IANA.
    Vérifie l'âge du cache local (30 jours) et retélécharge si nécessaire.
    """
    global _iana_cache
    filepath = get_cache_path()
    cache = load_iana_cache(filepath)

    should_download = force_download or cache is None

    if cache and not should_download:
        ts = cache.get("metadata", {}).get("timestamp", 0)
        age_seconds = time.time() - ts
        if age_seconds > CACHE_MAX_AGE_SECONDS:
            should_download = True
        else:
            days_old = int(age_seconds // 86400)
            sys.stderr.write(f"[IANA] Using cached IANA ports database ({days_old} days old)\n")
            _iana_cache = cache
            return cache

    if should_download:
        try:
            sys.stderr.write("[IANA] Downloading latest IANA port database...\n")
            csv_text = download_iana_csv()
            cache = parse_iana_csv(csv_text)
            save_iana_cache(cache, filepath)
            sys.stderr.write("[IANA] IANA ports database updated\n")
            _iana_cache = cache
            return cache
        except Exception as e:
            sys.stderr.write(f"[IANA] Download failed ({e}).\n")
            if cache:
                days_old = int((time.time() - cache.get("metadata", {}).get("timestamp", 0)) // 86400)
                sys.stderr.write(f"[IANA] Using cached IANA ports database ({days_old} days old)\n")
                _iana_cache = cache
                return cache

    _iana_cache = cache
    return cache


def _get_active_cache() -> dict | None:
    global _iana_cache
    if _iana_cache is None:
        _iana_cache = load_iana_cache()
    return _iana_cache


def get_service_name(port: int, protocol: str = "tcp") -> str:
    """
    Retourne le nom du service pour un port et un protocole.
    Ordre de résolution (3-tier) :
      1. Cache IANA
      2. Dictionnaire statique de fallback
      3. "unknown-service-{port}"
    """
    cache = _get_active_cache()
    proto_clean = protocol.lower().strip()
    key = f"{port}/{proto_clean}"

    if cache and "ports" in cache:
        entry = cache["ports"].get(key)
        if entry and entry.get("service"):
            return entry["service"]

    # Tier 2: Fallback statique
    static_name = STATIC_SERVICE_NAMES.get((port, proto_clean))
    if static_name:
        return static_name

    # Tier 3: Default fallback
    return f"unknown-service-{port}"


def get_all_known_ports() -> list[int]:
    """Retourne la liste de tous les ports uniques enregistrés dans le cache IANA."""
    cache = _get_active_cache()
    ports_set = set()
    if cache and "ports" in cache:
        for key in cache["ports"].keys():
            try:
                p_str = key.split("/")[0]
                ports_set.add(int(p_str))
            except Exception:
                pass
    if not ports_set:
        for p, _ in STATIC_SERVICE_NAMES.keys():
            ports_set.add(p)
    return sorted(list(ports_set))


# ── Compatibilité descendante ──────────────────────────────────────────────────
SERVICE_KEYWORDS = STATIC_SERVICE_KEYWORDS

class KnownPortsWrapper(dict):
    """Encapsulation rétrocompatible pour KNOWN_PORTS."""
    def get(self, key, default=None):
        if isinstance(key, str):
            cache = _get_active_cache()
            if cache and "services" in cache:
                pts = cache["services"].get(key.lower())
                if pts:
                    return pts
        return super().get(key, default)

    def __getitem__(self, key):
        val = self.get(key)
        if val is None:
            raise KeyError(key)
        return val

KNOWN_PORTS = KnownPortsWrapper({
    "nginx": [80, 443],
    "apache": [80, 443],
    "openssh": [22],
    "mysql": [3306],
    "redis": [6379],
})
