import socket

try:
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

def get_hostname_dns(ip):
    """
    Récupère le nom d'hôte via DNS inversé.
    """
    try:
        #gethostbyaddr renvoi 3 choses : le nom d'hôte, les alias et les adresses IP et on a besoin que du nom d'hote
        hostname, _, _ = socket.gethostbyaddr(ip)
        
        return hostname
    except Exception:
        return 'Unknown'

def get_mac_arp(ip):
    """
    Récupère l'adresse MAC via la commande système ARP.
    """
    import subprocess
    import re
    import os

    try:
        # Commande selon l'OS : "arp -a" sur Windows, "arp -n" sur Linux/Mac
        command = ["arp", "-a", ip] if os.name == 'nt' else ["arp", "-n", ip]

        # Exécution de la commande avec capture de la sortie
        result = subprocess.run(command, capture_output=True, text=True, timeout=2)
        
        if result.returncode != 0:
            return "Inconnu"

        # Recherche de la MAC avec la regex : ([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}
        mac_regex = r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
        match = re.search(mac_regex, result.stdout)

        return match.group(0) if match else "Inconnu"
    except Exception:
        return "Inconnu"

def estimate_os(ip):
    """
    Estime l'OS basé sur la valeur TTL d'un ping.
    Windows: ~128 | Linux: ~64 | Network: ~255
    """
    import platform
    import subprocess
    import re

    try:
        # Commande de ping (1 seul paquet)
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, "1", ip]
        
        result = subprocess.run(command, capture_output=True, text=True, timeout=2)
        if result.returncode != 0:
            return "Inconnu"

        # Recherche du TTL dans la sortie
        ttl_match = re.search(r"ttl=(\d+)", result.stdout.lower())
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 64: return "Linux/Unix"
            if ttl <= 128: return "Windows"
            if ttl <= 255: return "Équipement Réseau"
        return "Inconnu"
    except Exception:
        return "Inconnu"

def get_device_info(ip, is_public: bool = False):
    """
    Retourne hostname, MAC et OS estimé de l'appareil.
    """
    try:
        hostname = get_hostname_dns(ip)
        os_name = estimate_os(ip)
        
        if is_public:
            mac = "N/A (Public IP)"
        else:
            mac = get_mac_arp(ip)
            
        return {
            'ip': ip,
            'hostname': hostname,
            'mac': mac,
            'os': os_name
        }
    except Exception:
        return {
            'ip': ip,
            'hostname': 'Unknown',
            'mac': 'Unknown',
            'os': 'Unknown'
        }