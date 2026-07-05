import concurrent.futures
import ipaddress
import socket
import time
import sys

try:
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from .utils import parse_subnet
    from .device_info import get_device_info
except ImportError:
    try:
        from scanner.utils import parse_subnet
        from scanner.device_info import get_device_info
    except ImportError:
        from utils import parse_subnet
        from device_info import get_device_info


# ──────────────────────────────────────────────────────────────
# Méthode 1 : Découverte ARP via Scapy (Couche 2 — détecte TOUT)
# ──────────────────────────────────────────────────────────────
def arp_scan(subnet, timeout=2):
    """
    Envoie des requêtes ARP sur tout le sous-réseau via Scapy.
    Détecte TOUS les appareils connectés (téléphones, PC, IoT, etc.)
    même ceux qui n'ont aucun port TCP ouvert.
    
    Retourne une liste de dicts {ip, mac}.
    """
    if not SCAPY_AVAILABLE:
        return []

    try:
        # Construire le paquet ARP broadcast
        arp_request = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        # Envoyer et recevoir les réponses (verbose=0 pour ne rien afficher)
        answered, _ = srp(packet, timeout=timeout, verbose=0)

        hosts = []
        for sent, received in answered:
            hosts.append({
                "ip": received.psrc,
                "mac": received.hwsrc
            })
        return hosts
    except OSError as e:
        sys.stderr.write(f"[ARP] Erreur scan ARP: {str(e)}\n")
        return []


# ──────────────────────────────────────────────────────────────
# Méthode 1B : Découverte via le cache ARP du système
# ──────────────────────────────────────────────────────────────
def system_arp_scan(subnet):
    """
    Lit la table ARP de l'OS (Windows/Linux) pour trouver les appareils
    qui ont récemment communiqué sur le réseau.
    Très efficace si Scapy manque de privilèges administrateur.
    """
    import subprocess
    import re
    import os
    
    hosts = []
    try:
        ips_in_subnet = set(parse_subnet(subnet))
        if not ips_in_subnet:
            return []
            
        command = ["arp", "-a"] if os.name == 'nt' else ["arp", "-n"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=5,
                                encoding="utf-8", errors="replace")
        
        if result.returncode != 0:
            return []

        pattern = r"(\d{1,3}(?:\.\d{1,3}){3})\s+.*?(?:ether\s+)?([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})"
        
        for line in result.stdout.splitlines():
            match = re.search(pattern, line)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace('-', ':').lower()
                
                # Ignorer les adresses de broadcast et vérifier le sous-réseau
                if ip in ips_in_subnet and not ip.endswith('.255') and not ip.endswith('.0'):
                    hosts.append({"ip": ip, "mac": mac})
    except Exception as e:
        sys.stderr.write(f"[ARP] Erreur system_arp_scan: {str(e)}\n")
        
    return hosts

# ──────────────────────────────────────────────────────────────
# Méthode 2 : TCP Ping (Couche 4 — fallback si ARP échoue)
# ──────────────────────────────────────────────────────────────
# Ports TCP pour détecter PC, téléphones, tablettes, TV, IoT
_DISCOVERY_TCP_PORTS = [
    80, 443, 22, 8080,           # Web / SSH
    135, 139, 445, 3389,        # Windows (PC)
    5353, 62078,                  # mDNS / iPhone (Apple)
    8008, 8009,                   # Chromecast / Google TV
    7000, 7100,                   # AirPlay (Apple TV, iPhone)
    5555,                         # Android (ADB, certains téléphones)
    8443, 8888,                   # TV / box / IoT
]


def tcp_ping(ip: str, ports=None, timeout=1) -> dict:
    """
    Tente de se connecter via un socket TCP à chaque port de la liste un par un.
    Si N'IMPORTE QUEL port accepte la connexion → l'hôte est actif.
    Enregistre quel port a répondu et utilise cela comme approximation de la latence.
    
    Ports ciblés : PC Windows, iPhone/iPad, Android, Chromecast/TV, AirPlay.
    """
    if ports is None:
        ports = _DISCOVERY_TCP_PORTS

    alive = False
    latency = None
    open_port = None
    hostname = "Unknown"
    mac = "Unknown"

    for port in ports:
        start_time = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                # connect_ex retourne 0 en cas de succès
                result = s.connect_ex((ip, port))
                
                if result == 0:
                    end_time = time.time()
                    latency = (end_time - start_time) * 1000  # Latence en ms
                    alive = True
                    open_port = port
                    break
        except OSError:
            continue

    os_name = "Unknown"
    if alive:
        try:
            device = get_device_info(ip)
            hostname = device.get("hostname", "Unknown")
            mac = device.get("mac", "Unknown")
            os_name = device.get("os", "Unknown")
        except Exception:
            pass

    return {
        "ip": ip,
        "hostname": hostname,
        "mac": mac,
        "os": os_name,
        "alive": alive,
        "latency": round(latency, 2) if latency is not None else None,
        "open_port": open_port
    }


# ──────────────────────────────────────────────────────────────
# Fonction Principale : Découverte Hybride (ARP + TCP)
# ──────────────────────────────────────────────────────────────
def scan_subnet(subnet, timeout=1, max_workers=200, host_callback=None, progress_callback=None):
    """
    Découverte réseau hybride en 2 phases :
      Phase 1 — Scan ARP (Scapy) : Détecte TOUS les appareils du réseau local
                en envoyant un broadcast ARP. Fonctionne même si aucun port
                n'est ouvert (téléphones, tablettes, IoT, etc.).
      Phase 2 — TCP Ping (fallback) : Si ARP échoue ou ne trouve rien,
                on revient à la méthode classique de connexion TCP.
    """
    alive_hosts = []
    found_ips = set()

    # ── Phase 1 : Scan ARP (Scapy + Cache système) ──
    sys.stderr.write(f"[DISCOVERY] Phase 1 : Scan ARP sur {subnet}...\n")
    arp_results = []
    
    if SCAPY_AVAILABLE:
        arp_results.extend(arp_scan(subnet, timeout=2))
        
    # Compléter avec le cache ARP système (fiable sans admin)
    arp_results.extend(system_arp_scan(subnet))
    
    # Déduplication
    unique_arp_results = {h["ip"]: h for h in arp_results}
    arp_results = list(unique_arp_results.values())

    for arp_host in arp_results:
        ip = arp_host["ip"]
        mac = arp_host["mac"]
        found_ips.add(ip)

        # Enrichir avec hostname et OS
        hostname = "Unknown"
        os_name = "Unknown"
        try:
            device = get_device_info(ip)
            hostname = device.get("hostname", "Unknown")
            os_name = device.get("os", "Unknown")
        except (OSError, KeyError, ValueError):
            pass

        host_data = {
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "os": os_name,
            "alive": True,
            "latency": None,
            "open_port": None
        }
        alive_hosts.append(host_data)
        if host_callback:
            host_callback(host_data)

    sys.stderr.write(f"[DISCOVERY] ARP : {len(arp_results)} appareils détectés.\n")

    # ── Phase 2 : TCP Ping (complément — trouve les appareils manqués par ARP) ──
    ips = parse_subnet(subnet)
    total_ips = len(ips)
    
    # On considère que la phase ARP représente 10% du travail, ou a scanné instantanément
    if progress_callback:
        progress_callback(min(total_ips, len(found_ips) + int(total_ips * 0.1)), total_ips)

    remaining_ips = [ip for ip in ips if ip not in found_ips]
    scanned_count = total_ips - len(remaining_ips)

    if remaining_ips:
        sys.stderr.write(
            f"[DISCOVERY] Phase 2 : TCP Ping sur {len(remaining_ips)} IP restantes...\n"
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(tcp_ping, ip, timeout=timeout): ip
                for ip in remaining_ips
            }

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                scanned_count += 1
                if progress_callback:
                    progress_callback(scanned_count, total_ips)

                if result.get("alive") and result["ip"] not in found_ips:
                    found_ips.add(result["ip"])
                    alive_hosts.append(result)
                    if host_callback:
                        host_callback(result)

    sys.stderr.write(f"[DISCOVERY] Total : {len(alive_hosts)} appareils actifs.\n")

    # Tri par adresse IP
    alive_hosts.sort(key=lambda x: ipaddress.ip_address(x["ip"]))

    return alive_hosts