"""
scanner/osint_enricher.py
-------------------------
Module d'enrichissement OSINT pour Smart Network Mapper.

Interroge l'API publique NVD (NIST) v2.0 pour récupérer les CVEs
connues associées aux services et versions détectés lors du scan.

L'API NVD est gratuite et ne nécessite pas de clé API
(limitée à 5 requêtes / 30 secondes sans clé).

Usage :
    from scanner.osint_enricher import enrich_with_cves
    cve_results = enrich_with_cves(scan_ports_data)
"""

import re
import time
import json
import urllib.request
import urllib.parse
import urllib.error
import ssl


# ──────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 10        # Timeout par requête (secondes)
DELAY_BETWEEN_REQUESTS = 6  # Pause entre requêtes (respect rate limit NVD)
MAX_CVE_PER_SERVICE = 5     # Nombre max de CVEs à retourner par service


try:
    from .iana_manager import SERVICE_KEYWORDS
except ImportError:
    try:
        from scanner.iana_manager import SERVICE_KEYWORDS
    except ImportError:
        from iana_manager import SERVICE_KEYWORDS



def _extract_version_number(version_string):
    """Extrait le numéro de version propre depuis une bannière."""
    if not version_string or version_string in ["N/A", "Non détectée", "Réponse vide"]:
        return ""
    # Chercher un pattern type X.Y.Z ou X.Y
    match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version_string)
    return match.group(1) if match else ""


def _extract_software_name(version_string, service_name):
    """Extrait le nom du logiciel depuis la bannière ou le service."""
    if version_string and "/" in version_string:
        return version_string.split("/")[0].strip().lower()
    
    service_lower = service_name.lower() if service_name else ""
    return SERVICE_KEYWORDS.get(service_lower, service_lower)


def _build_search_keyword(software_name, version_number):
    """Construit le mot-clé de recherche pour l'API NVD."""
    keyword = software_name
    if version_number:
        keyword += f" {version_number}"
    return keyword.strip()


def _query_nvd(keyword):
    """
    Interroge l'API NVD v2.0 avec un mot-clé.
    Retourne la liste brute des CVEs ou une liste vide en cas d'erreur.
    """
    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": MAX_CVE_PER_SERVICE
    })
    url = f"{NVD_API_URL}?{params}"

    ctx = ssl.create_default_context()

    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "SmartNetworkMapper/1.0"
        })
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("vulnerabilities", [])
    except urllib.error.HTTPError as e:
        if e.code == 403:
            # Rate limit atteint, on attend et on réessaye une fois
            time.sleep(DELAY_BETWEEN_REQUESTS * 2)
            try:
                with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=ctx) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data.get("vulnerabilities", [])
            except Exception:
                return []
        return []
    except Exception:
        return []


# ──────────────────────────────────────────────────────────────
# Catalogue CISA KEV (Known Exploited Vulnerabilities)
# ──────────────────────────────────────────────────────────────
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Base de signatures critiques d'exploits actifs connus (Fallback hors-ligne immédiat)
_CORE_CISA_KEV_SET = {
    "CVE-2024-6387",  # regreSSHion (OpenSSH)
    "CVE-2023-38408", # OpenSSH PKCS#11 RCE
    "CVE-2021-44228", # Log4Shell
    "CVE-2021-45046", # Log4j RCE
    "CVE-2021-41773", # Apache HTTP Path Traversal
    "CVE-2021-42013", # Apache HTTP RCE
    "CVE-2017-0144",  # EternalBlue (SMBv1)
    "CVE-2019-0708",  # BlueKeep (RDP)
    "CVE-2020-1472",  # Zerologon
    "CVE-2021-26855", # Microsoft Exchange ProxyLogon
    "CVE-2021-34527", # PrintNightmare
    "CVE-2022-22965", # Spring4Shell
    "CVE-2023-34362", # MOVEit Transfer RCE
    "CVE-2022-26134", # Atlassian Confluence OGNL
    "CVE-2023-27997", # Fortinet FortiOS SSL-VPN RCE
    "CVE-2024-21762", # FortiOS Out-of-bounds Write RCE
    "CVE-2023-4966",  # Citrix Bleed
    "CVE-2024-3400",  # Palo Alto Networks PAN-OS RCE
}


def is_cisa_kev(cve_id: str) -> bool:
    """
    Vérifie si une CVE fait partie du catalogue officiel CISA KEV
    (failles activement exploitées dans la nature par des attaquants).
    """
    if not cve_id or not isinstance(cve_id, str):
        return False
    return cve_id.strip().upper() in _CORE_CISA_KEV_SET


def _parse_cve_entry(vuln_item):
    """
    Parse une entrée CVE brute de l'API NVD et retourne un dict propre enrichi CISA KEV.
    """
    cve = vuln_item.get("cve", {})
    cve_id = cve.get("id", "N/A")

    # Description (en anglais par défaut)
    descriptions = cve.get("descriptions", [])
    description = "Aucune description disponible."
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", description)
            break
    # Tronquer la description si trop longue
    if len(description) > 200:
        description = description[:197] + "..."

    # Score CVSS (v3.1 prioritaire, sinon v3.0, sinon v2.0)
    cvss_score = 0.0
    severity = "AUCUNE"
    
    metrics = cve.get("metrics", {})
    
    # Essayer CVSS v3.1
    cvss_v31 = metrics.get("cvssMetricV31", [])
    if cvss_v31:
        cvss_data = cvss_v31[0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore", 0.0)
        severity = cvss_data.get("baseSeverity", "NONE")
    else:
        # Essayer CVSS v3.0
        cvss_v30 = metrics.get("cvssMetricV30", [])
        if cvss_v30:
            cvss_data = cvss_v30[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "NONE")
        else:
            # Essayer CVSS v2.0
            cvss_v2 = metrics.get("cvssMetricV2", [])
            if cvss_v2:
                cvss_data = cvss_v2[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = "CRITICAL" if cvss_score >= 9.0 else \
                           "HIGH" if cvss_score >= 7.0 else \
                           "MEDIUM" if cvss_score >= 4.0 else "LOW"

    # Date de publication
    published = cve.get("published", "")[:10]  # Format YYYY-MM-DD

    # Lien officiel NVD
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    # Vérification CISA KEV (Exploitation active)
    has_active_exploit = is_cisa_kev(cve_id)

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "severity": severity,
        "published": published,
        "url": nvd_url,
        "is_cisa_kev": has_active_exploit,
        "threat_tag": "🔥 CISA KEV (EXPLOIT ACTIF)" if has_active_exploit else "NVD CVE"
    }


# ──────────────────────────────────────────────────────────────
# API Publique
# ──────────────────────────────────────────────────────────────
def enrich_with_cves(open_ports_data, progress_callback=None):
    """
    Enrichit les données de scan avec les CVEs connues depuis NVD.

    Args:
        open_ports_data: Liste de dicts avec les infos des ports ouverts
                         (chaque dict doit avoir: port, service, version)
        progress_callback: Fonction optionnelle appelée avec (service, index, total)

    Returns:
        Dict {port: [liste de CVEs]} où chaque CVE est un dict avec:
            cve_id, description, cvss_score, severity, published, url
    """
    results = {}
    
    # Dédupliquer les services pour éviter des requêtes en double
    # (ex: si port 80 et 8080 ont tous les deux "apache")
    seen_keywords = {}  # keyword -> port qui l'a demandé en premier
    queries = []  # (port, keyword)

    for port_info in open_ports_data:
        port = port_info.get("port", 0)
        service = port_info.get("service", "")
        version = port_info.get("version", "")

        software = _extract_software_name(version, service)
        version_num = _extract_version_number(version)
        
        # Si aucune version exacte n'est détectée, on ignore l'OSINT pour éviter
        # de polluer le rapport avec des milliers de vieilles failles historiques absurdes.
        if not version_num:
            results[port] = []
            continue

        keyword = _build_search_keyword(software, version_num)

        if not keyword or len(keyword) < 3:
            results[port] = []
            continue

        if keyword in seen_keywords:
            # Même service/version déjà interrogé, on copiera les résultats
            results[port] = f"__copy__{seen_keywords[keyword]}"
            continue

        seen_keywords[keyword] = port
        queries.append((port, keyword))

    # Exécuter les requêtes NVD
    total = len(queries)
    for idx, (port, keyword) in enumerate(queries):
        if progress_callback:
            progress_callback(keyword, idx + 1, total)

        raw_cves = _query_nvd(keyword)
        parsed = [_parse_cve_entry(v) for v in raw_cves]
        
        # Trier par score CVSS décroissant
        parsed.sort(key=lambda x: x["cvss_score"], reverse=True)
        results[port] = parsed

        # Respecter le rate limit NVD (6 secondes entre chaque requête)
        if idx < total - 1:
            time.sleep(DELAY_BETWEEN_REQUESTS)

    # Résoudre les copies (services dupliqués)
    for port in list(results.keys()):
        val = results[port]
        if isinstance(val, str) and val.startswith("__copy__"):
            source_port = int(val.replace("__copy__", ""))
            results[port] = results.get(source_port, [])

    return results


# ──────────────────────────────────────────────────────────────
# Test rapide
# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Simuler des résultats de scan pour tester
    test_ports = [
        {"port": 22,  "service": "ssh",  "version": "OpenSSH/8.2p1"},
        {"port": 80,  "service": "http", "version": "Apache/2.4.41"},
        {"port": 443, "service": "https", "version": "nginx/1.18.0"},
    ]

    print("=" * 60)
    print("  TEST OSINT ENRICHER - Requêtes NVD")
    print("=" * 60)

    def on_progress(svc, idx, total):
        print(f"\n[{idx}/{total}] Recherche CVEs pour : {svc}")

    cve_data = enrich_with_cves(test_ports, progress_callback=on_progress)

    for port, cves in cve_data.items():
        print(f"\n--- Port {port} ({len(cves)} CVEs) ---")
        for cve in cves:
            print(f"  {cve['cve_id']} | CVSS: {cve['cvss_score']} | {cve['severity']}")
            print(f"    {cve['description'][:100]}")
