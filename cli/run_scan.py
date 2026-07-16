#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cli/run_scan.py
---------------
Script d'exécution automatique et non-interactif pour Smart Network Mapper.
Spécifiquement conçu pour être piloté à distance par n8n (via SSH ou exécution directe).

Usage :
  1. Découverte du réseau local :
     python cli/run_scan.py --discover
     
  2. Scan ciblé d'un hôte :
     python cli/run_scan.py --target <IP> --mode <fast|full>
"""

import os

# Fix pour Scapy appelé depuis n8n (node.js child_process) sur Windows
if os.name == 'nt':
    if 'ProgramFiles' not in os.environ:
        os.environ['ProgramFiles'] = os.environ.get('PROGRAMFILES', 'C:\\Program Files')
    if 'ProgramFiles(x86)' not in os.environ:
        os.environ['ProgramFiles(x86)'] = os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)')

import sys
import json
import argparse
from datetime import datetime

# Ajustement du sys.path pour importer les packages frères (scanner, model, reporter)
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.env import load_dotenv
load_dotenv(project_root)

# Importations des modules internes du projet
try:
    from scanner.utils import detect_lan_config
    from scanner.host_discovery import scan_subnet
    from scanner.port_scanner import scan_ports
    from scanner.constants import TOP_PORTS, TOP_UDP_PORTS, EXTENDED_UDP_PORTS
    from scanner.osint_enricher import enrich_with_cves
    from scanner.iana_manager import init_iana_database
    from model.predictor import predict
    from reporter.html_generator import generate_html_report
    from reporter.telegram_utils import split_telegram_message, format_telegram_chunks

    init_iana_database()
except ImportError as e:
    print(json.dumps({
        "success": False,
        "error": f"Import error: {str(e)}",
        "error_message": f"Import error: {str(e)}",
        "phase": "init",
    }, ensure_ascii=True))
    sys.exit(0)
def _emit_error(message: str, phase: str = "scan") -> None:
    """Émet une erreur JSON lisible par n8n (exit 0 pour que stdout soit parsable)."""
    print(json.dumps({
        "success": False,
        "error": message,
        "error_message": message,
        "phase": phase,
    }, ensure_ascii=True, indent=2))
    sys.exit(0)


def handle_discover():
    """Détecte le réseau local et renvoie les machines actives en JSON."""
    config = detect_lan_config()
    if not config:
        _emit_error("Aucune interface réseau active détectée.", phase="discover")

    subnet = config.get("cidr")
    if not subnet:
        _emit_error("Impossible de déterminer le sous-réseau (CIDR).", phase="discover")
        
    try:
        # Scan du sous-réseau en arrière-plan sans affichage console interactif
        hosts = scan_subnet(subnet, timeout=1, max_workers=150)
        
        output = {
            "success": True,
            "interface": config.get("interface"),
            "local_ip": config.get("ip"),
            "subnet": subnet,
            "hosts": hosts
        }
        print(json.dumps(output, ensure_ascii=True, indent=2))
    except Exception as e:
        _emit_error(f"Échec de la découverte réseau : {str(e)}", phase="discover")

def handle_scan(target_ip, mode):
    """Effectue un scan de ports sur une cible, prédit les risques avec l'IA et enregistre les rapports."""
    # Détermination des ports à scanner
    if mode == "full":
        ports_to_scan = list(range(1, 65536))
    else:
        ports_to_scan = TOP_PORTS

    # Déduplication
    ports_to_scan = sorted(list(set(ports_to_scan)))

    # Scan TCP + UDP (ports UDP critiques en mode rapide)
    try:
        udp_ports = TOP_UDP_PORTS if mode == "fast" else EXTENDED_UDP_PORTS
        resultats_bruts = scan_ports(
            target_ip,
            ports_to_scan,
            progress_callback=None,
            include_udp=True,
            udp_ports=udp_ports,
        )
    except Exception as e:
        _emit_error(f"Échec du scan de ports : {str(e)}", phase="scan")

    def _port_key(item):
        return f"{item.get('port', 0)}:{item.get('protocole', 'TCP')}"

    open_ports = [res for res in resultats_bruts if res["statut"] == "ouvert"]

    ml_predictions = {}
    for item in open_ports:
        port = item.get("port", 0)
        version = item.get("version", "N/A")
        service = item.get("service", "")
        protocol = item.get("protocole", "TCP").lower()

        try:
            pred = predict(
                port=port,
                version_string=version if version not in ["Non détectée", "N/A"] else "",
                service=service,
                protocol=protocol,
            )
            ml_predictions[_port_key(item)] = {
                "vulnerable": pred["vulnerable"],
                "confidence": round(pred["confidence"], 4),
                "label": pred["label"],
            }
        except Exception:
            ml_predictions[_port_key(item)] = {
                "vulnerable": None,
                "confidence": 0.0,
                "label": "Error in prediction",
            }

    # ── Enrichissement OSINT (CVEs depuis NVD) ──────────────────
    cve_data = {}
    if open_ports:
        try:
            import sys as _sys
            _sys.stderr.write("[OSINT] Recherche de CVEs sur NVD...\n")
            cve_data = enrich_with_cves(
                open_ports,
                progress_callback=lambda svc, idx, total: _sys.stderr.write(
                    f"[OSINT] ({idx}/{total}) {svc}\n"
                )
            )
            _sys.stderr.write(f"[OSINT] Terminé. CVEs trouvées pour {sum(1 for v in cve_data.values() if v)} services.\n")
        except Exception as e:
            import sys as _sys
            _sys.stderr.write(f"[OSINT] Erreur (non bloquante): {str(e)}\n")
            cve_data = {}

    # Structuration du rapport JSON final
    date_jour = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data = { 
        "cible": target_ip,
        "date": date_jour,
        "source": "CLI Auto",
        "total_scanned": len(resultats_bruts),
        "ports": []
    }
    
    # Remplir les données des ports
    for res in resultats_bruts:
        if res["statut"] == "ouvert":
            port = res["port"]
            proto = res.get("protocole", "TCP")
            pred = ml_predictions.get(_port_key(res), {})
            port_cves = cve_data.get(port, [])
            data["ports"].append({
                "port": port,
                "protocole": proto,
                "statut": "ouvert",
                "service": res["service"],
                "version": res.get("version", "N/A"),
                "banner": res.get("banner", "N/A"),
                "vulnerable": pred.get("vulnerable", None),
                "confidence": pred.get("confidence", None),
                "label": pred.get("label", "N/A"),
                "cves": port_cves,
            })

    # Écriture dans le dossier outputs
    outputs_dir = os.path.join(project_root, "outputs")
    os.makedirs(outputs_dir, exist_ok=True)
    
    json_path = os.path.join(outputs_dir, "scan_result.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    try:
        from gui.db import init_db, insert_scan
        init_db()
        open_ports = len(data["ports"])
        vuln_ports = sum(1 for p in data["ports"] if p.get("vulnerable") == 1)
        insert_scan(
            target=target_ip,
            date=date_jour,
            duration=0.0,
            open_ports=open_ports,
            vuln_ports=vuln_ports,
            total_ports=len(resultats_bruts),
            json_path=json_path,
            source="CLI Auto",
            raw_data=json.dumps(data, ensure_ascii=False)
        )
    except Exception as e:
        pass

    # Génération du rapport HTML visuel
    html_path = os.path.join(outputs_dir, "report.html")
    html_generated = False
    n8n_dir = os.path.join(os.path.expanduser("~"), ".n8n-files")
    
    try:
        generate_html_report(data, html_path)
        html_generated = True
        
        # Copie dans le dossier autorisé par n8n (.n8n-files) pour contourner l'erreur de permission
        import shutil
        os.makedirs(n8n_dir, exist_ok=True)
        n8n_html_path = os.path.join(n8n_dir, "report.html")
        shutil.copy(html_path, n8n_html_path)
        
        # On donne à n8n le chemin vers le fichier qu'il a le droit de lire
        html_path = n8n_html_path
    except Exception as e:
        pass

    # Génération du rapport d'analyse IA (Groq)
    ai_report_path = os.path.join(outputs_dir, "ai_report.md")
    ai_generated = False
    ai_report_text = ""
    try:
        from reporter.ai_generator import generate_ai_report
        generate_ai_report(data, output_path=ai_report_path)
        ai_generated = True
        
        # Copie dans le dossier autorisé par n8n (.n8n-files) et lecture du texte
        if os.path.exists(ai_report_path):
            with open(ai_report_path, "r", encoding="utf-8") as f:
                ai_report_text = f.read()
            
            import shutil
            os.makedirs(n8n_dir, exist_ok=True)
            n8n_ai_path = os.path.join(n8n_dir, "ai_report.md")
            shutil.copy(ai_report_path, n8n_ai_path)
            ai_report_path = n8n_ai_path
    except Exception as e:
        import sys as _sys
        _sys.stderr.write(f"[AI] Erreur génération: {str(e)}\n")

    ai_report_chunks = format_telegram_chunks(split_telegram_message(ai_report_text))

    final_output = {
        "success": True,
        "cible": target_ip,
        "date": date_jour,
        "json_report_path": json_path,
        "html_report_path": html_path,
        "html_generated": html_generated,
        "ai_report_path": ai_report_path,
        "ai_generated": ai_generated,
        "ai_report_text": ai_report_text,
        "ai_report_chunks": ai_report_chunks,
        "ai_report_chunk_count": len(ai_report_chunks),
        "scan_data": data,
    }
    print(json.dumps(final_output, ensure_ascii=True, indent=2))

def main():
    parser = argparse.ArgumentParser(description="Smart Network Mapper CLI Automation Wrapper")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--discover", action="store_true", help="Auto-detect subnet and discover active hosts")
    group.add_argument("--target", type=str, help="Target IP address for scanning")
    
    parser.add_argument("--mode", choices=["fast", "full"], default="fast", help="Scan mode: fast (22 top ports) or full (1-65535)")
    
    args = parser.parse_args()

    if args.discover:
        handle_discover()
    elif args.target:
        handle_scan(args.target, args.mode)

if __name__ == "__main__":
    main()
