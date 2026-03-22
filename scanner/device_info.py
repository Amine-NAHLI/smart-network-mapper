import socket

def get_hostname_dns(ip):
    """
    Récupère le nom d'hôte à l'aide d'une requête DNS (socket.gethostbyaddr).
    Retourne une chaîne de caractères avec le nom d'hôte ou 'Unknown' en cas d'échec.
    """
    try:
        # La fonction gethostbyaddr renvoie un tuple (hostname, aliaslist, ipaddrlist)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        # En cas d'erreur (ex: aucune résolution DNS possible), on retourne 'Unknown'
        return 'Unknown'

def get_hostname_nmap(ip, nm):
    """
    Récupère le nom d'hôte à partir d'un objet nmap.PortScanner déjà scanné.
    Utilise nm[ip].hostname() et retourne 'Unknown' s'il n'est pas trouvé ou en cas d'erreur.
    """
    try:
        hostname = nm[ip].hostname()
        if hostname:
            return hostname
        return 'Unknown'
    except Exception:
        # Si la clé IP n'existe pas ou en cas de crash, on retourne 'Unknown'
        return 'Unknown'

def get_mac(ip, nm):
    """
    Récupère l'adresse MAC à partir de l'objet nmap.
    Retourne l'adresse MAC (ou 'Unknown' en cas de problème).
    """
    mac = 'Unknown'
    
    try:
        # Tenter d'obtenir l'adresse MAC
        mac = nm[ip]['addresses']['mac']
    except Exception:
        # Capturer les erreurs plus globales
        pass
        
    return mac

def get_device_info(ip, nm):
    """
    Combine les différentes méthodes pour obtenir les informations complètes de l'appareil.
    Essaie d'abord le nom d'hôte DNS, si 'Unknown', essaie nmap, puis récupère le MAC.
    Retourne un dictionnaire avec les clés : ip, hostname, mac.
    """
    try:
        # Essayer en premier la résolution DNS
        hostname = get_hostname_dns(ip)
        
        # Si la résolution DNS échoue, essayer avec l'objet nmap
        if hostname == 'Unknown':
            hostname = get_hostname_nmap(ip, nm)
            
        # Récupérer l'adresse MAC
        mac = get_mac(ip, nm)
        
        # Retourner le dictionnaire final avec toutes les données rassemblées
        return {
            'ip': ip,
            'hostname': hostname,
            'mac': mac
        }
    except Exception:
        # Un bloc try/except global pour s'assurer que la fonction ne plante pas et retourne toujours un dictionnaire valide
        return {
            'ip': ip,
            'hostname': 'Unknown',
            'mac': 'Unknown'
        }
