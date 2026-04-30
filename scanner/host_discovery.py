import concurrent.futures
import ipaddress
import socket
import time

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

def tcp_ping(ip: str, ports=[80, 443, 22, 8080], timeout=1) -> dict:
    """
    Tente de se connecter via un socket TCP à chaque port de la liste un par un.
    Si N'IMPORTE QUEL port accepte la connexion → l'hôte est actif.
    Enregistre quel port a répondu et utilise cela comme approximation de la latence.
    """
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
        except Exception:
            continue

    if alive:
        try:
            device = get_device_info(ip)
            hostname = device.get("hostname", "Unknown")
            mac = device.get("mac", "Unknown")
        except Exception:
            pass

    return {
        "ip": ip,
        "hostname": hostname,
        "mac": mac,
        "alive": alive,
        "latency": round(latency, 2) if latency is not None else None,
        "open_port": open_port
    }

def scan_subnet(subnet, timeout=1, max_workers=200, host_callback=None):
    """
    Scanne un sous-réseau en utilisant tcp_ping pour chaque hôte.
    """
    ips = parse_subnet(subnet)
    alive_hosts = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Remplacement de ping_host par tcp_ping avec keyword timeout
        futures = {executor.submit(tcp_ping, ip, timeout=timeout): ip for ip in ips}

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result.get("alive"):
                alive_hosts.append(result)
                if host_callback:
                    host_callback(result)

    # Tri par adresse IP
    alive_hosts.sort(key=lambda x: ipaddress.ip_address(x["ip"]))

    return alive_hosts