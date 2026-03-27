import sys
import os
import json
from datetime import datetime

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class MockColor:
        def __getattr__(self, name):
            return ""
    Fore = Style = MockColor()

from tqdm import tqdm
import ipaddress
from scanner.utils import validate_cidr, is_public_ip
from scanner.host_discovery import scan_subnet, tcp_ping
from scanner.port_scanner import scan_ports

# Ports les plus communs
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
    Affiche uniquement les ports ouverts dans un tableau final.
    """
    ports_ouverts = [r for r in resultats if r["statut"] == "ouvert"]

    column_port, column_protocol, column_service, column_status = "Port", "Protocole", "Service", "Statut"

    border = "+" + "-"*10 + "+" + "-"*12 + "+" + "-"*15 + "+" + "-"*12 + "+"
    print(border)
    print(f"| {column_port[:8].ljust(8)} | {column_protocol[:10].ljust(10)} | {column_service[:13].ljust(13)} | {column_status[:10].ljust(10)} |")
    print(border)

    if not ports_ouverts:
        message = "Aucun port ouvert trouvé".ljust(53)
        print(f"| {Fore.YELLOW}{message}{Style.RESET_ALL} |")
        print(border)
        return

    for res in ports_ouverts:
        port_padded = str(res["port"])[:8].ljust(8)
        protocol_padded = "TCP"[:10].ljust(10)
        service_padded = res["service"][:13].ljust(13)
        status_padded = "Ouvert"[:10].ljust(10)

        print(f"| {port_padded} | {protocol_padded} | {service_padded} | {Fore.GREEN}{status_padded}{Style.RESET_ALL} |")

    print(border)


def choisir_mode_scan():
    """
    Affiche le menu de sélection du mode de scan et retourne la liste de ports à scanner.
    """
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
            print(f"    {Fore.CYAN}→{Style.RESET_ALL}  Port unique       : {Fore.WHITE}80{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}→{Style.RESET_ALL}  Plusieurs ports   : {Fore.WHITE}80,443,22{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}→{Style.RESET_ALL}  Plage de ports    : {Fore.WHITE}1-1024{Style.RESET_ALL}")

            saisie = input(f"\n  {Fore.WHITE}Entrez le(s) port(s) : {Style.RESET_ALL}").strip()

            ports = []
            try:
                if "-" in saisie and "," not in saisie:
                    debut, fin = saisie.split("-")
                    debut, fin = int(debut.strip()), int(fin.strip())
                    if 1 <= debut <= fin <= 65535:
                        ports = list(range(debut, fin + 1))
                        print(f"  {Fore.YELLOW}[~] Durée estimée : ~{max(1, (fin - debut) // 1000)} seconde(s){Style.RESET_ALL}")
                    else:
                        print(f"  {Fore.RED}[✘] Plage invalide — les ports doivent être entre 1 et 65535.{Style.RESET_ALL}")
                        continue

                elif "," in saisie:
                    ports = [int(p.strip()) for p in saisie.split(",") if 1 <= int(p.strip()) <= 65535]
                    print(f"  {Fore.YELLOW}[~] Durée estimée : ~{max(1, len(ports) // 10)} seconde(s){Style.RESET_ALL}")

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


def save_json(target_ip, resultats):
    """
    Sauvegarde les résultats du scan dans outputs/scan_result.json.
    Le fichier est écrasé à chaque nouveau scan.
    """
    os.makedirs("outputs", exist_ok=True)

    date_jour = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    data = {
        "cible": target_ip,
        "date": date_jour,
        "ports": []
    }

    for res in resultats:
        if res["statut"] == "ouvert":
            data["ports"].append({
                "port": res["port"],
                "protocole": "TCP",
                "statut": "ouvert",
                "service": res["service"]
            })

    output_path = os.path.join("outputs", "scan_result.json")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    print(f"\n  {Fore.GREEN}[✔] Résultats sauvegardés dans '{output_path}'.{Style.RESET_ALL}")


def main():
    # STEP 1 - Banner
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════╗")
    print(f"║                                                          ║")
    print(f"║           SMART NETWORK MAPPER SCANNER                  ║")
    print(f"║                   by Amine Nahli                        ║")
    print(f"║                                                          ║")
    print(f"╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

    # STEP 2 - LAN Discovery
    print(f"\n{Fore.CYAN}┌──────────────────────────────────────────────────────────┐")
    print(f"│  ÉTAPE 1 — Découverte des hôtes sur le réseau           │")
    print(f"└──────────────────────────────────────────────────────────┘{Style.RESET_ALL}")

    while True:
        subnet = input(f"\n  {Fore.WHITE}Sous-réseau cible (ex: 192.168.1.0/24) : {Style.RESET_ALL}").strip()
        if validate_cidr(subnet):
            break
        else:
            print(f"  {Fore.RED}[✘] Format CIDR invalide — veuillez entrer un sous-réseau valide.{Style.RESET_ALL}")

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

    # STEP 3 - Ask scan choice
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
        # Handling Choice 1 (LAN Hôte)
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
        # Handling Choice 2 (Public IP)
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

    # STEP 6 - Call choisir_mode_scan()
    ports_a_scanner = choisir_mode_scan()

    # STEP 7 - Run scan_ports() with tqdm
    print(f"\n  {Fore.YELLOW}[→] Lancement du scan — {len(ports_a_scanner)} port(s) sur {target_ip}{Style.RESET_ALL}\n")
    pbar = tqdm(
        total=len(ports_a_scanner),
        desc="  Progression",
        unit="port",
        bar_format="  {l_bar}{bar:40}{r_bar}"
    )

    def pbar_update():
        pbar.update(1)

    try:
        resultats = scan_ports(target_ip, ports_a_scanner, progress_callback=pbar_update)
    except KeyboardInterrupt:
        pbar.close()
        print(f"\n  {Fore.YELLOW}[!] Scan interrompu par l'utilisateur.{Style.RESET_ALL}")
        sys.exit(0)
    pbar.close()

    # STEP 8 - Display results, call save_json(), display_ports_table()
    print(f"\n{Fore.CYAN}┌──────────────────────────────────────────────────────────┐")
    print(f"│  RÉSULTATS DU SCAN                                       │")
    print(f"└──────────────────────────────────────────────────────────┘{Style.RESET_ALL}\n")

    for res in resultats:
        port = res["port"]
        statut = res["statut"]
        service = res["service"]

        if statut == "ouvert":
            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL}  Port {port}/TCP   {Fore.GREEN}OUVERT{Style.RESET_ALL}    ({service})")
        elif statut == "fermé":
            print(f"  {Fore.RED}[-]{Style.RESET_ALL}  Port {port}/TCP   {Fore.RED}FERMÉ{Style.RESET_ALL}     ({service})")
        else:
            print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL}  Port {port}/TCP   {Fore.YELLOW}{statut.upper()}{Style.RESET_ALL}    ({service})")

    save_json(target_ip, resultats)
    print(f"\n  {Fore.BLUE}[→] Récapitulatif — ports ouverts uniquement :{Style.RESET_ALL}\n")
    display_ports_table(resultats)

    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════╗")
    print(f"║               Scan terminé avec succès                  ║")
    print(f"╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()