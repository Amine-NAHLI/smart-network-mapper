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

# Importations des modules internes du projet
try:
    from scanner.utils import detect_lan_config
    from scanner.host_discovery import scan_subnet, tcp_ping
    from scanner.port_scanner import scan_ports
    from model.predictor import predict
    from reporter.html_generator import generate_html_report
except ImportError as e:
    print(json.dumps({"error": f"Import error: {str(e)}"}))
    sys.exit(1)

TOP_PORTS = [ 
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135,
    139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443
]

def handle_discover():
    """Détecte le réseau local et renvoie les machines actives en JSON."""
    config = detect_lan_config()
    if not config:
        print(json.dumps({"error": "No active network interface detected."}))
        sys.exit(1)
        
    subnet = config.get("cidr")
    if not subnet:
        print(json.dumps({"error": "Unable to determine CIDR for the interface."}))
        sys.exit(1)
        
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
        print(json.dumps({"error": f"Discovery failed: {str(e)}"}))
        sys.exit(1)

def handle_scan(target_ip, mode):
    """Effectue un scan de ports sur une cible, prédit les risques avec l'IA et enregistre les rapports."""
    # Détermination des ports à scanner
    if mode == "full":
        ports_to_scan = list(range(1, 65536))
    else:
        ports_to_scan = TOP_PORTS

    # Déduplication
    ports_to_scan = sorted(list(set(ports_to_scan)))

    # Scan de ports (non-interactif, sans progress bar tqdm sur stdout pour n8n)
    try:
        resultats_bruts = scan_ports(target_ip, ports_to_scan, progress_callback=None)
    except Exception as e:
        print(json.dumps({"error": f"Port scan failed: {str(e)}"}))
        sys.exit(1)

    # Filtrer uniquement les ports avec statut "ouvert" pour l'IA
    open_ports = [res for res in resultats_bruts if res["statut"] == "ouvert"]
    
    # Prédictions IA locales (Random Forest)
    ml_predictions = {}
    for item in open_ports:
        port = item.get("port", 0)
        version = item.get("version", "N/A")
        service = item.get("service", "")
        
        try:
            pred = predict(
                port=port,
                version_string=version if version not in ["Non détectée", "N/A"] else "",
                service=service,
                protocol="tcp"
            )
            ml_predictions[port] = {
                "vulnerable": pred["vulnerable"],
                "confidence": round(pred["confidence"] * 100, 2),
                "label": pred["label"]
            }
        except Exception:
            ml_predictions[port] = {
                "vulnerable": None,
                "confidence": 0.0,
                "label": "Error in prediction"
            }

    # Structuration du rapport JSON final
    date_jour = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data = { 
        "cible": target_ip,
        "date": date_jour,
        "ports": []
    }
    
    # Remplir les données des ports
    for res in resultats_bruts:
        if res["statut"] == "ouvert":
            port = res["port"]
            pred = ml_predictions.get(port, {})
            data["ports"].append({
                "port": port,
                "protocole": "TCP",
                "statut": "ouvert",
                "service": res["service"],
                "version": res.get("version", "N/A"),
                "banner": res.get("banner", "N/A"),
                "vulnerable": pred.get("vulnerable", None),
                "confidence": pred.get("confidence", None),
                "label": pred.get("label", "N/A")
            })

    # Écriture dans le dossier outputs
    outputs_dir = os.path.join(project_root, "outputs")
    os.makedirs(outputs_dir, exist_ok=True)
    
    json_path = os.path.join(outputs_dir, "scan_result.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    # Génération du rapport HTML visuel
    html_path = os.path.join(outputs_dir, "report.html")
    html_generated = False
    try:
        generate_html_report(data, html_path)
        html_generated = True
        
        # Copie dans le dossier autorisé par n8n (.n8n-files) pour contourner l'erreur de permission
        import shutil
        n8n_dir = os.path.join(os.path.expanduser("~"), ".n8n-files")
        os.makedirs(n8n_dir, exist_ok=True)
        n8n_html_path = os.path.join(n8n_dir, "report.html")
        shutil.copy(html_path, n8n_html_path)
        
        # On donne à n8n le chemin vers le fichier qu'il a le droit de lire
        html_path = n8n_html_path
    except Exception as e:
        # Enregistré dans le JSON final pour n8n
        pass

    # Sortie finale en JSON pour n8n
    final_output = {
        "success": True,
        "cible": target_ip,
        "date": date_jour,
        "json_report_path": json_path,
        "html_report_path": html_path,
        "html_generated": html_generated,
        "scan_data": data
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
