import concurrent.futures
import ipaddress
from icmplib import ping

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

def ping_host(ip, timeout=1):
    """
    Envoie un ping à une seule adresse IP en utilisant icmplib.
    """
    try:
        host = ping(str(ip), count=1, timeout=timeout)
        #str(ip) → convertit l'adresse IP en chaîne de caractères
        #count=1 → nombre de pings à envoyer
        #timeout=timeout → délai d'attente pour chaque ping
        
        device = get_device_info(str(ip))
        
        return {
            "ip": str(ip),
            "hostname": device.get("hostname", "Unknown"),
            "mac": device.get("mac", "Unknown"),
            "alive": host.is_alive,
            #host.is_alive → true si allumée, false si éteinte
            "latency": host.avg_rtt if host.is_alive else None
            #host.avg_rtt → temps moyen de réponse en ms
        }
    except Exception:
        # Capturer les erreurs : adresse invalide ou ping sans réponse
        return {
            "ip": str(ip),
            "hostname": 'Unknown',
            "mac": 'Unknown',
            "alive": False,
            "latency": None
        }

def scan_subnet(subnet, timeout=1, max_workers=100):
    """
    Pingue tous les hôtes d'un sous-réseau simultanément pour découvrir les hôtes actifs.
    """
    #ips est une liste d'adresses ip
    ips = parse_subnet(subnet)
    #parse_subnet → appelle parse_subnet de utils pour obtenir une liste d'adresses ip
    
    alive_hosts = []
    #alive_hosts → liste qui va contenir les adresses ip des hôtes actifs

    # Je crée une équipe de 100 agents, chaque agent va pinger une IP
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:

        # Je donne à chaque agent une tâche : ping_host(ip, timeout)
        # futures est un dictionnaire qui associe chaque tâche à l'adresse IP correspondante
        """
        Ce qui se passe réellement :
        executor.submit(ping_host, "192.168.1.1") → Thread 1 démarre
        executor.submit(ping_host, "192.168.1.2") → Thread 2 démarre
        executor.submit(ping_host, "192.168.1.3") → Thread 3 démarre
        ... 100 threads en parallèle ...
        """
        futures = {executor.submit(ping_host, ip, timeout): ip for ip in ips}

        for future in concurrent.futures.as_completed(futures):
            #une fois que chaque agent a terminé son travail, je récupère son résultat
            result = future.result()
            if result.get("alive"):
                # Afficher les détails de l'hôte actif au fur et à mesure de leur découverte
                print(f"[+] Host {result['ip']:<15} is alive (Latency: {result['latency']} ms)")
                alive_hosts.append(result)

    #Trie par ordre numérique
    alive_hosts.sort(key=lambda x: ipaddress.ip_address(x["ip"]))

    return alive_hosts