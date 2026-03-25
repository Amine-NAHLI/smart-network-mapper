import socket

def get_hostname_dns(ip):
    """
    Récupère le nom d'hôte via DNS inversé.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return 'Unknown'

def get_mac_arp(ip):
    """
    Récupère l'adresse MAC via ARP (sans nmap).
    """
    try:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp
        
        # Envoie une requête ARP à l'IP et attend la réponse
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        result = srp(packet, timeout=1, verbose=0)[0]
        
        if result:
            return result[0][1].hwsrc
        return 'Unknown'
    except Exception:
        return 'Unknown'

def get_device_info(ip):
    """
    Retourne hostname et MAC de l'appareil.
    """
    try:
        hostname = get_hostname_dns(ip)
        mac = get_mac_arp(ip)
        return {
            'ip': ip,
            'hostname': hostname,
            'mac': mac
        }
    except Exception:
        return {
            'ip': ip,
            'hostname': 'Unknown',
            'mac': 'Unknown'
        }