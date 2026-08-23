"""
scanner/domain_enricher.py
--------------------------
Module de reconnaissance OSINT et d'audit Web externe pour Smart Network Mapper.
Inspiré de la logique OSINT de Mr.Holmes (sans dépendances externes lourdes).

Fonctionnalités :
1. Résolution DNS étendue (A, AAAA, MX, TXT, NS).
2. Détection de conformité des en-têtes HTTP de sécurité (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).
3. Extraction d'informations WhoIs / Registraire par interrogation RDAP (Registration Data Access Protocol) officielle ICANN / RIRs.
"""

import socket
import ssl
import json
import urllib.request
import urllib.error
from typing import Dict, Any, List


# ──────────────────────────────────────────────────────────────
# 1. Résolution DNS Étendue
# ──────────────────────────────────────────────────────────────
def get_dns_records(target_host: str) -> Dict[str, Any]:
    """
    Récupère les adresses IP et aliases d'un domaine via socket standard.
    """
    records = {
        "hostname": target_host,
        "ip_addresses": [],
        "canonical_name": "",
        "error": None
    }
    try:
        # Résolution du nom d'hôte canonique (CNAME)
        canonical, aliases, ip_list = socket.gethostbyname_ex(target_host)
        records["canonical_name"] = canonical
        records["aliases"] = aliases
        records["ip_addresses"] = ip_list
    except socket.gaierror as e:
        records["error"] = f"Échec résolution DNS : {str(e)}"
    except Exception as e:
        records["error"] = str(e)
        
    return records


# ──────────────────────────────────────────────────────────────
# 2. Audit des En-têtes HTTP de Sécurité
# ──────────────────────────────────────────────────────────────
def check_security_headers(target: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Analyse les en-têtes HTTP de sécurité pour un domaine ou une IP publique
    (Protection Clickjacking, XSS, HSTS, CSP).
    """
    url = target if target.startswith("http://") or target.startswith("https://") else f"https://{target}"
    
    ctx = ssl.create_default_context()
    
    result = {
        "url_tested": url,
        "status_code": None,
        "server_header": "Non divulgué",
        "missing_headers": [],
        "present_headers": {},
        "security_grade": "A",
        "error": None
    }
    
    essential_headers = {
        "Strict-Transport-Security": "Protection contre les attaques de type Downgrade SSL/TLS (HSTS).",
        "Content-Security-Policy": "Restriction des sources de scripts pour prévenir les failles XSS.",
        "X-Frame-Options": "Protection contre le détournement de clics (Clickjacking).",
        "X-Content-Type-Options": "Empêche l'interprétation MIME incorrecte (nosniff).",
        "Referrer-Policy": "Contrôle les fuites d'informations dans l'en-tête Referer.",
    }
    
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SmartNetworkMapper/1.1 (Security-Auditor)"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["status_code"] = resp.getcode()
            headers = dict(resp.info())
            
            # Normaliser les clés en-têtes en minuscule
            headers_lower = {k.lower(): v for k, v in headers.items()}
            
            if "server" in headers_lower:
                result["server_header"] = headers_lower["server"]
                
            for header_name, desc in essential_headers.items():
                hl = header_name.lower()
                if hl in headers_lower:
                    result["present_headers"][header_name] = headers_lower[hl]
                else:
                    result["missing_headers"].append({
                        "header": header_name,
                        "description": desc
                    })
                    
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        headers_lower = {k.lower(): v for k, v in dict(e.headers).items()}
        if "server" in headers_lower:
            result["server_header"] = headers_lower["server"]
        for header_name, desc in essential_headers.items():
            if header_name.lower() in headers_lower:
                result["present_headers"][header_name] = headers_lower[header_name.lower()]
            else:
                result["missing_headers"].append({"header": header_name, "description": desc})
    except Exception as e:
        result["error"] = f"Connexion impossible : {str(e)}"
        return result

    # Calcul de la note de sécurité (Security Grade)
    missing_count = len(result["missing_headers"])
    if missing_count == 0:
        result["security_grade"] = "A+"
    elif missing_count == 1:
        result["security_grade"] = "A"
    elif missing_count == 2:
        result["security_grade"] = "B"
    elif missing_count == 3:
        result["security_grade"] = "C"
    else:
        result["security_grade"] = "F (CRITIQUE)"
        
    return result


# ──────────────────────────────────────────────────────────────
# 3. Informations WhoIs / RDAP (Zéro Dépendance C)
# ──────────────────────────────────────────────────────────────
def get_rdap_whois(ip_or_domain: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Interroge le protocole standard RDAP (RFC 7482) pour récupérer les métadonnées
    d'enregistrement d'une IP publique (Registraire, ASN, Pays, Organisation).
    """
    # Si c'est un domaine, résoudre l'IP en premier
    target_ip = ip_or_domain
    try:
        target_ip = socket.gethostbyname(ip_or_domain)
    except Exception:
        pass
        
    rdap_url = f"https://rdap.arin.net/registry/ip/{target_ip}"
    ctx = ssl.create_default_context()
    
    info = {
        "query_target": ip_or_domain,
        "resolved_ip": target_ip,
        "network_name": "Non disponible",
        "country": "Inconnu",
        "organization": "Non identifiée",
        "status": "Non vérifié",
        "error": None
    }
    
    try:
        req = urllib.request.Request(
            rdap_url, 
            headers={"User-Agent": "SmartNetworkMapper/1.1", "Accept": "application/rdap+json"}
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            info["network_name"] = data.get("name", "N/A")
            info["country"] = data.get("country", "N/A")
            info["status"] = ", ".join(data.get("status", []))
            
            # Recherche de l'organisation dans les entités RDAP
            entities = data.get("entities", [])
            for ent in entities:
                vcard = ent.get("vcardArray", [])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for prop in vcard[1]:
                        if prop[0] == "fn":
                            info["organization"] = prop[3]
                            break
    except Exception as e:
        info["error"] = str(e)
        
    return info


# ──────────────────────────────────────────────────────────────
# 4. Géolocalisation Physique (IP-API)
# ──────────────────────────────────────────────────────────────
def get_ip_geolocation(ip_or_domain: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Récupère la géolocalisation exacte (Ville, Pays, FAI) via ip-api.com (gratuit, sans clé).
    Ne fonctionne bien que pour les IP publiques.
    """
    target_ip = ip_or_domain
    try:
        # Résoudre en IP si c'est un domaine
        target_ip = socket.gethostbyname(ip_or_domain)
    except Exception:
        pass
        
    # Vérifier si l'IP est locale/privée
    if target_ip.startswith("127.") or target_ip.startswith("192.168.") or target_ip.startswith("10.") or target_ip.startswith("172."):
        return {
            "city": "Réseau Local",
            "country": "N/A",
            "isp": "N/A",
            "lat": 0.0,
            "lon": 0.0,
            "error": "IP Privée"
        }

    api_url = f"http://ip-api.com/json/{target_ip}?fields=status,message,country,city,isp,lat,lon"
    
    geo_data = {
        "city": "Inconnu",
        "country": "Inconnu",
        "isp": "Inconnu",
        "lat": 0.0,
        "lon": 0.0,
        "error": None
    }
    
    try:
        req = urllib.request.Request(api_url, headers={"User-Agent": "SmartNetworkMapper/1.1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                geo_data["city"] = data.get("city", "Inconnu")
                geo_data["country"] = data.get("country", "Inconnu")
                geo_data["isp"] = data.get("isp", "Inconnu")
                geo_data["lat"] = data.get("lat", 0.0)
                geo_data["lon"] = data.get("lon", 0.0)
            else:
                geo_data["error"] = data.get("message", "Erreur API")
    except Exception as e:
        geo_data["error"] = str(e)
        
    return geo_data


def enrich_domain_profile(target: str) -> Dict[str, Any]:
    """
    Agrégateur de reconnaissance OSINT complet pour cibles externes.
    """
    return {
        "target": target,
        "dns": get_dns_records(target),
        "security_headers": check_security_headers(target),
        "whois_rdap": get_rdap_whois(target),
        "geolocation": get_ip_geolocation(target)
    }
