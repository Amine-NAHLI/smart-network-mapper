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
    Récupère l'adresse MAC via ARP
    """
    if not SCAPY_AVAILABLE:
        return 'Unknown'

    try:
        #cree un paquet arp qui va etre envoyer a tous les adresse ip pour leur di voila cette ip si tu a cette adresse ip renvoie moi ton adresse mac
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        # / veut dire qu'on va combiner les deux paquets on va demander a qui cette adresse ip et pour tous le monde c'est ce 
        #broadcast contient tous les machine et arp_request contient l'adresse ip qu'on veut connaitre son adresse mac =le message


        #c'est ici que le paquet est envoyer et on attend la reponse
        #[0] prendre juste les machines qui ont repondu 
        result = srp(packet, timeout=1, verbose=0)[0]
        
        if result:
            return result[0][1].hwsrc
            """
            result[0][1] → dans cette réponse, on prend le paquet reçu [1] (pas celui qu'on a envoyé [0]).
            .hwsrc → dans ce paquet, on extrait l'adresse MAC de la machine qui a répondu (hw = hardware, src = source).
            """
        return 'Unknown'
    except Exception:
        return 'Unknown'

def get_device_info(ip, is_public: bool = False):
    """
    Retourne hostname et MAC de l'appareil.
    """
    try:
        hostname = get_hostname_dns(ip)
        
        if is_public:
            mac = "N/A (Public IP)"
        else:
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