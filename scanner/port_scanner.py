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

def grab_banner(ip: str, port: int, timeout=2) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            
            # Probes spécifiques pour certains ports
            if port in [80, 8080, 8443, 443]:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else "Réponse vide"
    except socket.timeout:
        return "ERREUR: Timeout"
    except ConnectionRefusedError:
        return "FERMÉ / pas de réponse"
    except Exception as e:
        return f"ERREUR: {type(e).__name__}"

def extract_version(banner: str) -> str:
    # Si le banner indique une erreur ou un port fermé
    if "ERREUR" in banner or "FERMÉ" in banner or "Réponse vide" in banner:
        return "Non détectée"
        
    try:
        # Pattern simple pour extraire les versions (e.g., Apache/2.4.1)
        pattern = r'([\w\-]+)[/ ]([\d]+\.[\d]+[\.\d]*)'
        match = re.search(pattern, banner)
        if match:
            return f"{match.group(1)}/{match.group(2)}"
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
