import socket
import concurrent.futures
import re

# Récupérer le nom du service
def get_service(port: int) -> str:
    try:
        # On essaie d'obtenir le nom du service associé au port
        service = socket.getservbyport(port, "tcp")
        return service.upper()
    except OSError:
        return "INCONNU"

def grab_banner(ip: str, port: int, timeout=2.5) -> str:
    """
    Tente de récupérer la bannière du service en utilisant des sondes spécifiques.
    """
    # Dictionnaire des sondes par port (Probes)
    PROBES = {
        80:   b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n",
        8080: b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n",
        443:  b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n",
        6379: b"INFO\r\n",                                # Redis
        3306: b"\x07\x00\x00\x01\x00\x00\x00",           # MySQL Client Init
        21:   b"HELP\r\n",                                # FTP
        25:   b"EHLO scanner.local\r\n",                  # SMTP
        110:  b"CAPA\r\n",                                # POP3
        143:  b"A1 CAPABILITY\r\n",                       # IMAP
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            
            # 1. On vérifie si le service parle de lui-même (SSH, FTP, etc.)
            try:
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner: return banner
            except socket.timeout:
                pass # Si le service attend qu'on parle, on continue vers les sondes
            
            # 2. On envoie la sonde spécifique si elle existe
            if port in PROBES:
                s.sendall(PROBES[port])
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner if banner else "Réponse vide"
            
            # 3. Sonde générique pour les autres ports
            s.sendall(b"\r\n\r\n")
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else "Réponse vide"

    except Exception as e:
        return f"ERREUR: {type(e).__name__}"

def extract_version(banner: str) -> str:
    """
    Extrait intelligemment le nom du logiciel et sa version.
    Ignore les versions de protocoles (HTTP/1.1) pour éviter de tromper l'IA.
    """
    if any(x in banner for x in ["ERREUR", "FERMÉ", "Réponse vide"]):
        return "Non détectée"
        
    try:
        # 1. Cas particulier du WEB : on cherche la ligne "Server:"
        if "HTTP/" in banner:
            server_match = re.search(r"Server: ([\w\-_]+)[/ \-]([\d]+\.[\d]+[\.\d\w\-]*)", banner, re.IGNORECASE)
            if server_match:
                return f"{server_match.group(1)}/{server_match.group(2)}"

        # 2. Pattern général
        pattern = r'([\w\-_]+)[/ \-]([\d]+\.[\d]+[\.\d\w\-]*)'
        matches = re.finditer(pattern, banner)
        
        for match in matches:
            name = match.group(1)
            ver = match.group(2)
            
            # On ignore les versions de protocole pur
            if name.upper() in ["HTTP", "SSH", "TCP"]:
                continue
            
            return f"{name}/{ver}"
            
        return "Version inconnue"
    except Exception:
        return "Erreur d'analyse"

def scan_tcp(ip: str, port: int) -> dict:
    """
    Teste si un port TCP est ouvert sur une IP donnée avec une gestion d'erreurs améliorée.
    """
    try: 
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5) 
            # connect() lève une exception en cas d'échec, ce qui permet de capturer le type d'erreur
            s.connect((ip, port))
            
            statut = "ouvert"
            service = get_service(port)
            banner = grab_banner(ip, port)
            version = extract_version(banner)
            
            return {
                "port": port,
                "statut": statut,
                "service": service,
                "banner": banner,
                "version": version
            }
    except ConnectionRefusedError:
        return {
            "port": port,
            "statut": "fermé",
            "service": get_service(port),
            "banner": "FERMÉ / pas de réponse",
            "version": "N/A"
        }
    except socket.timeout:
        return {
            "port": port,
            "statut": "filtré/timeout",
            "service": get_service(port),
            "banner": "ERREUR: Timeout",
            "version": "N/A"
        }
    except Exception as e:
        return {
            "port": port,
            "statut": "erreur",
            "service": get_service(port),
            "banner": f"ERREUR: {type(e).__name__}",
            "version": "N/A"
        }

def scan_ports(ip: str, ports: list, progress_callback=None) -> list:
    """
    Scanne une liste de ports en multi-threading avec ThreadPoolExecutor.
    """
    resultats = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        futures = {executor.submit(scan_tcp, ip, port): port for port in set(ports)}
        
        for future in concurrent.futures.as_completed(futures):
            try:
                res = future.result()
                resultats.append(res)
            except Exception as e:
                port = futures[future]
                resultats.append({
                    "port": port,
                    "statut": "erreur",
                    "service": get_service(port),
                    "banner": f"ERREUR: {type(e).__name__}",
                    "version": "N/A"
                })
            
            if progress_callback:
                progress_callback()
    
    # Tri par numéro de port pour une lecture plus claire (style Nmap)
    resultats.sort(key=lambda x: x["port"])
    return resultats
