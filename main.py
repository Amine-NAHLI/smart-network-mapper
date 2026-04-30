import sys #arreter le prog proprement au cas d'erreur
import os #cree le dossier des outpus si il nexsite pas
import json #pour sauvegarder les resultats JSON
# import requests (supprimé car l'IA est maintenant appelée localement)
from datetime import datetime #POUR LA DATE ET LHEURE DES RESULTATS

try:
    from colorama import Fore, Style, init
    #AJOUTER LES COULEURS au terminal
    init(autoreset=True)
except ImportError:
    #si c'est pas installer on utilise mockcolor pour forcer lutilisation des couleurs 
    class MockColor:
        def __getattr__(self, name):
            return ""
    Fore = Style = MockColor()

import socket #pour travailler avec le reseau
try:
    import psutil #pour obtenir les informations sur le reseau(on va pas arreter le prog si c'est pas installer car il y'a possibilite de le faire manuellement)
except ImportError:
    psutil = None

from tqdm import tqdm #pour afficher les barres de progression
import ipaddress #valider et calculer des adresses IP
from scanner.utils import validate_cidr, is_public_ip, detect_lan_config
from scanner.host_discovery import scan_subnet, tcp_ping
from scanner.port_scanner import scan_ports

TOP_PORTS = [ 
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135,
    139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443
]


def display_hosts_table(hosts):
    """
    Affiche la liste des hôtes dans un tableau bien formaté.
    """
    column_ip, column_hostname, column_mac, column_status, column_latency = "IP Address", "Hostname", "MAC Address", "Status", "Latency (ms)"

    border = "+" + "-"*17 + "+" + "-"*22 + "+" + "-"*19 + "+" + "-"*12 + "+" + "-"*15 + "+"
    print(border)
    print(f"| {column_ip[:15].ljust(15)} | {column_hostname[:20].ljust(20)} | {column_mac[:17].ljust(17)} | {column_status[:10].ljust(10)} | {column_latency[:13].ljust(13)} |")
    print(border)

    if not hosts:
        message = "Aucun hôte actif trouvé".ljust(86)
        print(f"| {Fore.YELLOW}{message}{Style.RESET_ALL} |")
        print(border)
        return

    for host in hosts:
        ip = host.get("ip", "Inconnu")
        hostname = str(host.get("hostname", "Inconnu"))
        mac = str(host.get("mac", "Inconnu"))
        alive = host.get("alive", False)
        latency = host.get("latency")

        status_text = "Actif" if alive else "Inactif"
        status_color = Fore.GREEN if alive else Fore.RED
        latency_str = f"{latency:.2f}" if latency is not None else "N/A"

        ip_padded = ip[:15].ljust(15)
        hostname_padded = hostname[:20].ljust(20)
        mac_padded = mac[:17].ljust(17)
        status_padded = status_text[:10].ljust(10)
        latency_padded = latency_str[:13].ljust(13)

        print(f"| {ip_padded} | {hostname_padded} | {mac_padded} | {status_color}{status_padded}{Style.RESET_ALL} | {latency_padded} |")

    print(border)


def display_ports_table(resultats):
    """
    Affiche les résultats du scan dans un tableau 
    """
    column_port = "PORT"
    column_status = "ÉTAT"
    column_service = "SERVICE"
    column_version = "VERSION"

    print(f"\n{Fore.WHITE}{column_port:<10} {column_status:<15} {column_service:<20} {column_version}{Style.RESET_ALL}")
    print("-" * 80)

    for res in resultats:
        port_protocol = f"{res['port']}/tcp" #on ajoute /tcp pour indiquer que c'est un port tcp
        status = res["statut"].upper() #on met le statut en majuscule
        service = res["service"].lower() #on met le service en minuscule
        
        if res["statut"] == "ouvert":
            status_color = Fore.GREEN
            version = res.get("version", "Inconnue") #on recupere la version
            if version == "Non détectée" or version == "N/A":
                version = res.get("banner", "Inconnue")[:40] #on recupere la banniere
        elif res["statut"] == "fermé":
            status_color = Fore.RED
            version = ""
        else:
            status_color = Fore.YELLOW
            # Pour les erreurs, on affiche le message d'erreur (stocké dans banner)
            version = res.get("banner", "")

        print(f"{port_protocol:<10} {status_color}{status:<15}{Style.RESET_ALL} {service:<20} {version}")

    print("-" * 80)




def choisir_mode_scan():
    
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════╗")
    print(f"║              SÉLECTION DU MODE DE SCAN                  ║")
    print(f"╠══════════════════════════════════════════════════════════╣")
    print(f"║  {Fore.GREEN}[ 1 ]{Fore.CYAN}  Scan Rapide      — 22 ports communs   {Fore.YELLOW}(~5 sec){Fore.CYAN}    ║")
    print(f"║  {Fore.YELLOW}[ 2 ]{Fore.CYAN}  Scan Complet     — 65 535 ports       {Fore.YELLOW}(~5-10 min){Fore.CYAN} ║")
    print(f"║  {Fore.BLUE}[ 3 ]{Fore.CYAN}  Scan Personnalisé — port(s) précis    {Fore.YELLOW}(immédiat){Fore.CYAN}  ║")
    print(f"╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

    while True:
        choix = input(f"\n  {Fore.WHITE}Votre choix (1/2/3) : {Style.RESET_ALL}").strip()

        if choix == "1":
            print(f"\n  {Fore.GREEN}[✔] Mode sélectionné : Scan Rapide — 22 ports{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}[~] Durée estimée : environ 5 secondes{Style.RESET_ALL}")
            return TOP_PORTS

        elif choix == "2":
            print(f"\n  {Fore.YELLOW}[✔] Mode sélectionné : Scan Complet — 65 535 ports{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}[~] Durée estimée : 5 à 10 minutes selon le réseau{Style.RESET_ALL}")
            confirmation = input(f"\n  {Fore.RED}[!] Cette opération peut être longue. Confirmer ? (o/n) : {Style.RESET_ALL}").strip().lower()
            if confirmation == "o":
                return list(range(1, 65536))
            else:
                print(f"\n  {Fore.YELLOW}[!] Annulé — veuillez choisir un autre mode.{Style.RESET_ALL}")

        elif choix == "3":
            print(f"\n  {Fore.BLUE}[✔] Mode sélectionné : Scan Personnalisé{Style.RESET_ALL}")
            print(f"\n  {Fore.WHITE}Format accepté :{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}→{Style.RESET_ALL}  Port unique(exemple)       : {Fore.WHITE}80{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}→{Style.RESET_ALL}  Plusieurs ports(exemple)   : {Fore.WHITE}80,443,22{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}→{Style.RESET_ALL}  Plage de ports(exemple)    : {Fore.WHITE}1-1024{Style.RESET_ALL}")

            saisie = input(f"\n  {Fore.WHITE}Entrez le(s) port(s) : {Style.RESET_ALL}").strip()

            ports = []
            try:
                #si il saisie de scanner une plage de port
                if "-" in saisie and "," not in saisie:
                    debut, fin = saisie.split("-")
                    debut, fin = int(debut.strip()), int(fin.strip())
                    if 1 <= debut <= fin <= 65535:
                        ports = list(range(debut, fin + 1))
                        print(f"  {Fore.YELLOW}[~] Durée estimée : ~{max(1, (fin - debut) // 1000)} seconde(s){Style.RESET_ALL}")
                    else:
                        print(f"  {Fore.RED}[✘] Plage invalide — les ports doivent être entre 1 et 65535.{Style.RESET_ALL}")
                        continue

                #si il saisie de scanner plusieurs ports
                elif "," in saisie:
                    ports = [int(p.strip()) for p in saisie.split(",") if 1 <= int(p.strip()) <= 65535]
                    print(f"  {Fore.YELLOW}[~] Durée estimée : ~{max(1, len(ports) // 10)} seconde(s){Style.RESET_ALL}")

                #si il saisie de scanner un port unique
                else:
                    port = int(saisie)
                    if 1 <= port <= 65535:
                        ports = [port]
                        print(f"  {Fore.YELLOW}[~] Durée estimée : ~1 seconde{Style.RESET_ALL}")
                    else:
                        print(f"  {Fore.RED}[✘] Port invalide — doit être entre 1 et 65535.{Style.RESET_ALL}")
                        continue

                if ports:
                    return ports

            except ValueError:
                print(f"  {Fore.RED}[✘] Saisie invalide — utilisez le format : 80 | 80,443 | 1-1024{Style.RESET_ALL}")

        else:
            print(f"  {Fore.RED}[✘] Choix invalide — entrez 1, 2 ou 3.{Style.RESET_ALL}")


def save_json(target_ip, resultats, ml_predictions={}):
    """
    sauvegarde et Garantit une seule sauvegarde par scan.
    """
    os.makedirs("outputs", exist_ok=True) #créer le dossier outputs s'il n'existe pas

    date_jour = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    data = { 
        "cible": target_ip,
        "date": date_jour,
        "ports": []
    }
 
    for res in resultats:
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

    output_path = os.path.join("outputs", "scan_result.json") #créer le fichier scan_result.json dans le dossier outputs

    with open(output_path, "w", encoding="utf-8") as f: #ouvrir le fichier scan_result.json en mode écriture
        json.dump(data, f, indent=4, ensure_ascii=False) #écrire les données dans le fichier scan_result.json

    print(f"\n  {Fore.GREEN}[✔] Résultats sauvegardés dans '{output_path}'.{Style.RESET_ALL}")


from model.predictor import predict

def send_to_ml(resultats):
    """
    Filtre les ports ouverts et effectue les prédictions localement.
    """
    # 1. Filtre uniquement les ports avec statut "ouvert"
    open_ports = [res for res in resultats if res["statut"] == "ouvert"]
    if not open_ports:
        return {}

    print(f"\n  {Fore.BLUE}[→] Analyse IA en cours (chargement du modèle)...{Style.RESET_ALL}")
    
    predictions = {}
    try:
        for item in open_ports:
            port = item.get("port", 0)
            version = item.get("version", "")
            service = item.get("service", "")
            
            # Appel direct au modèle local
            pred = predict(
                port=port,
                version_string=version,
                service=service,
                protocol="tcp" # par défaut
            )
            
            predictions[port] = {
                "vulnerable": pred["vulnerable"],
                "confidence": round(pred["confidence"] * 100, 2),
                "label": pred["label"]
            }
        return predictions
    except Exception as e:
        print(f"\n  {Fore.RED}[✘] Erreur lors de l'analyse IA : {e}{Style.RESET_ALL}")
        
    return {}


def main():
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════╗")
    print(f"║                                                          ║")
    print(f"║           SMART NETWORK MAPPER SCANNER                  ║")
    print(f"║                   by Amine Nahli                        ║")
    print(f"║                                                          ║")
    print(f"╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}┌──────────────────────────────────────────────────────────┐")
    print(f"│  ÉTAPE 1 — Découverte des hôtes sur le réseau           │")
    print(f"└──────────────────────────────────────────────────────────┘{Style.RESET_ALL}")

    while True:
        print(f"\n  {Fore.WHITE}Que voulez-vous scanner ?{Style.RESET_ALL}")
        print(f"    {Fore.GREEN}[ 1 ]{Style.RESET_ALL}  Détecter et scanner mon réseau local automatiquement")
        print(f"    {Fore.YELLOW}[ 2 ]{Style.RESET_ALL}  Scanner un réseau spécifique (saisie manuelle CIDR)")
        
        init_choice = input(f"\n  {Fore.WHITE}Votre choix (1/2) : {Style.RESET_ALL}").strip()
        
        subnet = None

        if init_choice == "1":
            print(f"\n  {Fore.BLUE}[→] Recherche de la carte Wi-Fi active...{Style.RESET_ALL}")
            config = detect_lan_config()
            
            if not config:
                print(f"  {Fore.RED}[✘] Échec de la détection automatique (aucune interface Wi-Fi ou Ethernet active trouvée).{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}[!] Veuillez entrer le réseau manuellement.{Style.RESET_ALL}")
                while True:
                    subnet = input(f"\n  {Fore.WHITE}Sous-réseau cible (ex: 192.168.1.0/24) : {Style.RESET_ALL}").strip()
                    if validate_cidr(subnet):
                        break
                    print(f"  {Fore.RED}[✘] Format CIDR invalide.{Style.RESET_ALL}")
            else:
                print(f"  {Fore.GREEN}[✔] Réseau local détecté avec succès !{Style.RESET_ALL}")
                print(f"      {Fore.CYAN}•{Style.RESET_ALL} Interface utilisée : {Fore.WHITE}{config['interface']}{Style.RESET_ALL}")
                print(f"      {Fore.CYAN}•{Style.RESET_ALL} IP locale         : {Fore.WHITE}{config['ip']}{Style.RESET_ALL}")
                print(f"      {Fore.CYAN}•{Style.RESET_ALL} Masque réseau      : {Fore.WHITE}{config['netmask']}{Style.RESET_ALL}")
                print(f"      {Fore.CYAN}•{Style.RESET_ALL} Réseau détecté     : {Fore.YELLOW}{config['cidr']}{Style.RESET_ALL}")
                subnet = config['cidr']
            break

        elif init_choice == "2":
            while True:
                subnet = input(f"\n  {Fore.WHITE}Sous-réseau cible (ex: 192.168.1.0/24) : {Style.RESET_ALL}").strip()
                if validate_cidr(subnet):
                    break
                else:
                    print(f"  {Fore.RED}[✘] Format CIDR invalide — veuillez entrer un sous-réseau valide.{Style.RESET_ALL}")
            break
        else:
            print(f"  {Fore.RED}[✘] Choix invalide.{Style.RESET_ALL}")

    print(f"\n  {Fore.BLUE}[→] Scan du sous-réseau {subnet} en cours...{Style.RESET_ALL}\n")
    try:
        hosts = scan_subnet(subnet, timeout=1, max_workers=100)
    except KeyboardInterrupt:
        print(f"\n  {Fore.YELLOW}[!] Scan interrompu par l'utilisateur.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n  {Fore.RED}[✘] Une erreur s'est produite : {e}{Style.RESET_ALL}")
        sys.exit(1)

    print(f"  {Fore.GREEN}[✔] Scan terminé — affichage des hôtes détectés :{Style.RESET_ALL}\n")
    display_hosts_table(hosts)

    if not hosts:
        print(f"\n  {Fore.YELLOW}[!] Aucun hôte actif trouvé — fin du programme.{Style.RESET_ALL}")
        sys.exit(0)

    print(f"\n{Fore.WHITE}Que voulez-vous faire ?{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}[ 1 ]  Scanner un hôte de ce réseau{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}[ 2 ]  Scanner une IP externe (publique){Style.RESET_ALL}")
    print(f"  {Fore.CYAN}[ 3 ]  Quitter{Style.RESET_ALL}")

    while True:
        choice = input(f"\n  {Fore.WHITE}Votre choix (1/2/3) : {Style.RESET_ALL}").strip()
        if choice in ["1", "2", "3"]:
            break
        else:
            print(f"  {Fore.RED}[✘] Choix invalide — entrez 1, 2 ou 3.{Style.RESET_ALL}")

    if choice == "3":
        print(f"\n  {Fore.YELLOW}[!] Au revoir !{Style.RESET_ALL}\n")
        sys.exit(0)

    target_ip = None

    if choice == "1":
        print(f"\n  {Fore.BLUE}[→] Hôtes actifs disponibles :{Style.RESET_ALL}")
        for host in hosts:
            print(f"        {Fore.CYAN}•{Style.RESET_ALL}  {host['ip']}")

        while True:
            target_ip = input(f"\n  {Fore.WHITE}IP cible à scanner : {Style.RESET_ALL}").strip()
            if any(h["ip"] == target_ip for h in hosts):
                break
            else:
                print(f"  {Fore.RED}[✘] IP non trouvée — choisissez une IP dans la liste ci-dessus.{Style.RESET_ALL}")

    elif choice == "2":
        while True:
            target_ip_input = input(f"\n  {Fore.WHITE}Adresse IP publique cible : {Style.RESET_ALL}").strip()
            try:
                ip_obj = ipaddress.ip_address(target_ip_input)
                target_ip = str(ip_obj)
                if not is_public_ip(target_ip):
                    print(f"  {Fore.RED}[✘] Cette IP est privée — entrez une IP publique.{Style.RESET_ALL}")
                    continue
                break
            except ValueError:
                print(f"  {Fore.RED}[✘] Adresse IP invalide — veuillez réessayer.{Style.RESET_ALL}")

        print(f"  {Fore.BLUE}[→] Vérification de l'état de l'hôte...{Style.RESET_ALL}")
        res_ping = tcp_ping(target_ip)
        if not res_ping["alive"]:
            print(f"  {Fore.RED}[✘] Hôte injoignable via TCP — arrêt.{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"  {Fore.GREEN}[✔] Hôte actif — port {res_ping['open_port']} répond (latence: {res_ping['latency']:.2f} ms){Style.RESET_ALL}")

    # STEP 5 - Ask port scan
    scan_choice = input(f"\n  {Fore.WHITE}Voulez-vous scanner les ports de cette IP ? (o/n) : {Style.RESET_ALL}").strip().lower()
    if scan_choice != 'o':
        print(f"\n  {Fore.YELLOW}[!] Fin du programme — au revoir !{Style.RESET_ALL}\n")
        sys.exit(0)

    # STEP 6 - Select and deduplicate ports
    # BUG : Si l'utilisateur saisit deux fois le même port (ex: 80, 80), 
    # scan_ports créait deux threads et retournait deux résultats, provoquant des doublons.
    # SOLUTION : Utilisation de set() pour garantir l'unicité des ports avant le scan.
    raw_ports = choisir_mode_scan()
    ports_a_scanner = sorted(list(set(raw_ports)))

    # STEP 7 - Run scan_ports() with tqdm
    print(f"\n  {Fore.YELLOW}[→] Lancement du scan — {len(ports_a_scanner)} port(s) unique(s) sur {target_ip}{Style.RESET_ALL}\n")
    pbar = tqdm(
        total=len(ports_a_scanner),
        desc="  Progression",
        unit="port",
        bar_format="  {l_bar}{bar:40}{r_bar}"
    )

    def pbar_update():
        pbar.update(1)

    try:
        resultats_bruts = scan_ports(target_ip, ports_a_scanner, progress_callback=pbar_update)
    except KeyboardInterrupt:
        pbar.close()
        print(f"\n  {Fore.YELLOW}[!] Scan interrompu par l'utilisateur.{Style.RESET_ALL}")
        sys.exit(0)
    pbar.close()

    # Appel au serveur ML juste après pbar.close()
    ml_predictions = send_to_ml(resultats_bruts)

    # BUG : Même si scan_ports est propre, il est possible que des doublons surviennent par erreur.
    # SOLUTION : On utilise un dictionnaire {port: résultat} pour garantir qu'un même port
    # ne soit pas affiché ou sauvegardé deux fois.
    unique_results_dict = {res["port"]: res for res in resultats_bruts}
    resultats = sorted(unique_results_dict.values(), key=lambda x: x["port"])

    # STEP 8 - Display results, call save_json(), display_ports_table()
    # SOLUTION : Ces appels sont strictement isolés à la fin du flux principal, utilisant les données dédoublonnées.
    print(f"\n{Fore.CYAN}┌──────────────────────────────────────────────────────────┐")
    print(f"│  RÉSULTATS DU SCAN                                       │")
    print(f"└──────────────────────────────────────────────────────────┘{Style.RESET_ALL}\n")
 
    for i, res in enumerate(resultats): 
        port = res["port"]
        statut = res["statut"]
        service = res["service"]
        banner = res.get("banner", "")
        version = res.get("version", "N/A")
 
        if statut == "ouvert":
            # Header du port ouvert
            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Port {Fore.WHITE}{port}/TCP{Style.RESET_ALL} : {Fore.GREEN}OUVERT{Style.RESET_ALL} ({service}) -> {version}")
            
            # Préparation des lignes de détails
            details = []
            
            # 1. Banner
            exclude_banner = ["", None, "N/A", "Non détectée", "Réponse vide"]
            if banner and banner not in exclude_banner:
                details.append(("Banner    ", banner))
            
            # 2. Version
            exclude_version = ["", None, "N/A", "Non détectée", "Version inconnue"]
            if version and version not in exclude_version:
                details.append(("Version   ", version))
                
            # 3. Service
            details.append(("Service   ", service))
            
            # 4. ML Prediction (toujours en dernier)
            ml_text = f"{Fore.WHITE}⚪ Non analysé{Style.RESET_ALL}"
            if port in ml_predictions:
                pred = ml_predictions[port]
                conf = pred['confidence']
                if pred["vulnerable"] == 1:
                    ml_text = f"{Fore.RED}⚠️  VULNERABLE (confiance: {conf}%){Style.RESET_ALL}"
                else:
                    ml_text = f"{Fore.GREEN}✅ NON VULNERABLE (confiance: {conf}%){Style.RESET_ALL}"
            details.append(("ML        ", ml_text))

            # Affichage des détails avec branches Cyan
            for idx, (label, val) in enumerate(details):
                connector = "└─" if idx == len(details) - 1 else "├─"
                print(f"      {Fore.CYAN}{connector}{Style.RESET_ALL} {label}: {val}")
            
            # Ligne vide pour la lisibilité entre les ports ouverts (si ce n'est pas le dernier)
            print()

        elif statut == "fermé":
            print(f"  {Fore.RED}[-]{Style.RESET_ALL} Port {Fore.WHITE}{port}/TCP{Style.RESET_ALL} : {Fore.RED}FERMÉ{Style.RESET_ALL} ({service})")
        
        else:
            # Cas filtré / timeout
            print(f"  {Fore.YELLOW}[~]{Style.RESET_ALL} Port {Fore.WHITE}{port}/TCP{Style.RESET_ALL} : {Fore.YELLOW}FILTRÉ{Style.RESET_ALL} ({service})")
            raison = banner.replace("ERREUR: ", "") if banner else "Timeout"
            print(f"      {Fore.CYAN}└─{Style.RESET_ALL} Raison : {raison}")

    save_json(target_ip, resultats, ml_predictions)
    
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════╗")
    print(f"║               Scan terminé avec succès                  ║")
    print(f"╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()