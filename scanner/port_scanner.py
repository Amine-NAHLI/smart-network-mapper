import socket
import concurrent.futures
import re
import ssl

try:
    from .iana_manager import get_service_name
except ImportError:
    try:
        from scanner.iana_manager import get_service_name
    except ImportError:
        from iana_manager import get_service_name

# Ports UDP critiques scannés en mode rapide (DNS, SNMP, DHCP, NTP, etc.)
TOP_UDP_PORTS = [53, 67, 68, 69, 123, 161, 162, 500, 514, 1900]

# Sondes UDP par port (payload minimal pour provoquer une réponse)
UDP_PROBES = {
    53: (
        b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x01\x00\x01"
    ),
    123: b"\x1b" + 47 * b"\x00",
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04"
           b"\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30"
           b"\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
}

def get_service(port: int, protocol: str = "tcp") -> str:
    # Priorité 1 : résolution OS native (compatibilité existante)
    try:
        service = socket.getservbyport(port, protocol)
        return service.upper()
    except OSError:
        pass
    # Priorité 2 : enrichissement IANA pour les ports inconnus de l'OS
    srv = get_service_name(port, protocol)
    if srv != f"unknown-service-{port}":
        return srv.upper()
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
        8443: b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n",
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
            
            # Ajout de la couche SSL/TLS pour les ports sécurisés
            if port in [443, 8443, 993, 995, 465]:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                s = context.wrap_socket(s, server_hostname=ip)
            
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

    except ssl.SSLError:
        return "ERREUR SSL (Service non TLS ou cert invalide)"
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
        # Nettoyage spécifique pour SSH (ex: "SSH-2.0-dropbear_2020.81" -> "dropbear_2020.81")
        if banner.startswith("SSH-"):
            banner = re.sub(r"^SSH-\d+\.\d+-", "", banner)

        # 1. Cas particulier du WEB : on cherche la ligne "Server:"
        if "HTTP/" in banner or "Server:" in banner:
            # Gère les serveurs sans version (ex: "Server: thttpd") ou avec version (ex: "Server: Apache/2.4.58")
            server_match = re.search(r"Server:\s*([\w\-_]+)(?:[/ \-_]([\d]+\.[\d]+[\.\d\w\-]*))?", banner, re.IGNORECASE)
            if server_match:
                name = server_match.group(1)
                ver = server_match.group(2)
                return f"{name}/{ver}" if ver else name

        # 2. Cas spécifique de SSH / Dropbear
        ssh_match = re.search(r"OpenSSH[_-]([\d]+\.[\d]+[\w\.\-]*)", banner, re.IGNORECASE)
        if ssh_match:
            return f"OpenSSH/{ssh_match.group(1)}"
        
        dropbear_match = re.search(r"dropbear[_-]([\d]+\.[\d]+[\w\.\-]*)", banner, re.IGNORECASE)
        if dropbear_match:
            return f"dropbear/{dropbear_match.group(1)}"

        # 3. Pattern général (gère le _, le -, le / et l'espace comme séparateurs)
        pattern = r'([a-zA-Z][\w\-]*)[/ \-_v]+([\d]+\.[\d]+[\.\d\w\-]*)'
        matches = re.finditer(pattern, banner)
        
        for match in matches:
            name = match.group(1)
            ver = match.group(2)
            
            # On ignore les versions de protocole pur et les noms d'OS
            if name.upper() in ["HTTP", "SSH", "TCP", "UBUNTU", "DEBIAN", "CENTOS"]:
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
                "protocole": "TCP",
                "statut": statut,
                "service": service,
                "banner": banner,
                "version": version,
            }
    except ConnectionRefusedError:
        return {
            "port": port,
            "protocole": "TCP",
            "statut": "fermé",
            "service": get_service(port),
            "banner": "FERMÉ / pas de réponse",
            "version": "N/A",
        }
    except socket.timeout:
        return {
            "port": port,
            "protocole": "TCP",
            "statut": "filtré/timeout",
            "service": get_service(port),
            "banner": "ERREUR: Timeout",
            "version": "N/A",
        }
    except Exception as e:
        return {
            "port": port,
            "protocole": "TCP",
            "statut": "erreur",
            "service": get_service(port),
            "banner": f"ERREUR: {type(e).__name__}",
            "version": "N/A",
        }

def scan_udp(ip: str, port: int, timeout: float = 2.0) -> dict:
    """
    Teste un port UDP : envoie une sonde et attend une réponse.
    UDP sans réponse = fermé ou filtré (statut 'fermé/filtré').
    """
    service = get_service(port, "udp")
    probe = UDP_PROBES.get(port, b"\x00")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(probe, (ip, port))
            try:
                data, _ = s.recvfrom(1024)
                banner = data[:200].decode("utf-8", errors="replace").strip()
                if not banner:
                    banner = f"Réponse UDP ({len(data)} octets)"
                return {
                    "port": port,
                    "protocole": "UDP",
                    "statut": "ouvert",
                    "service": service,
                    "banner": banner,
                    "version": extract_version(banner) if banner else "Non détectée",
                }
            except socket.timeout:
                return {
                    "port": port,
                    "protocole": "UDP",
                    "statut": "fermé/filtré",
                    "service": service,
                    "banner": "Pas de réponse UDP",
                    "version": "N/A",
                }
    except Exception as e:
        return {
            "port": port,
            "protocole": "UDP",
            "statut": "erreur",
            "service": service,
            "banner": f"ERREUR: {type(e).__name__}",
            "version": "N/A",
        }


def scan_udp_ports(ip: str, ports: list | None = None, progress_callback=None) -> list:
    """Scanne une liste de ports UDP en multi-threading."""
    if ports is None:
        ports = TOP_UDP_PORTS

    resultats = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_udp, ip, port): port for port in set(ports)}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                resultats.append(future.result())
            except Exception as e:
                resultats.append({
                    "port": port,
                    "protocole": "UDP",
                    "statut": "erreur",
                    "service": get_service(port, "udp"),
                    "banner": f"ERREUR: {type(e).__name__}",
                    "version": "N/A",
                })
            if progress_callback:
                progress_callback()

    resultats.sort(key=lambda x: x["port"])
    return resultats


def scan_ports(ip: str, ports: list, progress_callback=None, include_udp: bool = False,
               udp_ports: list | None = None) -> list:
    """
    Scanne une liste de ports TCP (et optionnellement UDP) en multi-threading.
    """
    resultats = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        futures = {executor.submit(scan_tcp, ip, port): port for port in set(ports)}

        for future in concurrent.futures.as_completed(futures):
            try:
                res = future.result()
                res.setdefault("protocole", "TCP")
                resultats.append(res)
            except Exception as e:
                port = futures[future]
                resultats.append({
                    "port": port,
                    "protocole": "TCP",
                    "statut": "erreur",
                    "service": get_service(port),
                    "banner": f"ERREUR: {type(e).__name__}",
                    "version": "N/A",
                })

            if progress_callback:
                progress_callback()

    if include_udp:
        udp_results = scan_udp_ports(ip, udp_ports, progress_callback=progress_callback)
        resultats.extend(udp_results)

    resultats.sort(key=lambda x: (x.get("protocole", "TCP"), x["port"]))
    return resultats
