import ipaddress
import socket
try:
    import psutil
except ImportError:
    psutil = None

def parse_subnet(subnet):
    """
    Analyse une chaîne de sous-réseau CIDR et retourne une liste de toutes les adresses IP des hôtes.
    """
    try:    
        network = ipaddress.ip_network(subnet, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []

def validate_cidr(subnet):
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True 
    except ValueError:
        return False


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        
        excluded_ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
            ipaddress.ip_network("0.0.0.0/8"),
            ipaddress.ip_network("224.0.0.0/4"),
            ipaddress.ip_network("240.0.0.0/4")
        ]
        
        for network in excluded_ranges:
            if addr in network:
                return False
        
        return True
    except ValueError:
        return False

def detect_lan_config():
    """
    Détecte automatiquement la configuration du réseau local (IP, Masque, CIDR).
    Priorise le Wi-Fi, puis l'Ethernet, puis toute autre interface active.
    """
    if psutil is None:
        return None

    try:
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        all_configs = []

        for iface_name, addrs in interfaces.items():
            # Vérifier si l'interface est active
            if iface_name in stats and not stats[iface_name].isup:
                continue
            
            for addr in addrs:
                if addr.family == socket.AF_INET: # IPv4
                    ip = addr.address
                    netmask = addr.netmask
                    
                    # Ignorer loopback (127.x.x.x) et APIPA (169.254.x.x)
                    if ip.startswith("127.") or ip.startswith("169.254.") or not netmask:
                        continue
                    
                    try:
                        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        all_configs.append({
                            "interface": iface_name,
                            "ip": ip,
                            "netmask": netmask,
                            "cidr": str(network)
                        })
                    except Exception:
                        continue

        if not all_configs:
            return None

        # Priorisation intelligente
        # Wi-Fi
        wifi_keywords = ["wi-fi", "wifi", "wlan", "wlp"]
        wifi_interfaces = [c for c in all_configs if any(t in c["interface"].lower() for t in wifi_keywords)]
        
        # Ethernet / LAN
        eth_keywords = ["eth", "en", "ethernet", "local area", "lan", "p2p"]
        eth_interfaces = [c for c in all_configs if any(t in c["interface"].lower() for t in eth_keywords) and c not in wifi_interfaces]
        
        others = [c for c in all_configs if c not in wifi_interfaces and c not in eth_interfaces]

        if wifi_interfaces: return wifi_interfaces[0]
        if eth_interfaces: return eth_interfaces[0]
        if others: return others[0]

        return None
        
    except Exception:
        return None
