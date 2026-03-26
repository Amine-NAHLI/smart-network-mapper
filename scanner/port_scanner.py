import socket
import concurrent.futures

"""
cette fonction est Trouver le nom du service qui correspond à un numéro de port STOCKER Dans un fichier par defaut dans windows C:\Windows\System32\drivers\etc\services
"""

def get_service(port: int) -> str:
    """
    Si le service n'est pas trouvé, retourne 'INCONNU' avec socket.getservbyport()
    socket.getservbyport() est une fonction Python qui consulte une base de données locale sur ta machine
    """
    try:
        #on entre dans les argument le numero de port et le protocole (tcp)
        service = socket.getservbyport(port, "tcp")
        return service.upper()
        #upper pour que tous les retours soit majuscule
    except OSError:
        # Si le port n'est pas dans la base de données locale des services, on retourne 'INCONNU'
        return "INCONNU"

def scan_tcp(ip: str, port: int) -> dict:
    """
    Teste si un port TCP est ouvert sur une IP donnée.
    Retourne un dictionnaire avec le statut du port et le nom du service.
    """
    try:
        # Création d'un socket IPv4 (AF_INET) de type TCP (SOCK_STREAM)
        # AF_INET → tu utilises IPv4
        # SOCK_STREAM → tu utilises TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            # connect_ex renvoie 0 si la connexion réussit (port ouvert), sinon un code d'erreur
            # on n'utilise pas connect() car il lève une exception si le port est fermé
            result = s.connect_ex((ip, port))
            
            statut = "ouvert" if result == 0 else "fermé"
            
            # Récupération du nom du service uniquement si le port est ouvert
            service = get_service(port) if statut == "ouvert" else "INCONNU"
            
            return {
                "port": port,
                "statut": statut,
                "service": service
            }
    except Exception as e:
        # Gestion des erreurs réseaux ou système inattendues (ex: permission refusée)
        return {
            "port": port,
            "statut": "erreur",
            "service": "INCONNU",
            "erreur": str(e)
        }

def scan_ports(ip: str, ports: list, progress_callback=None) -> list:
    """
    Scanne une liste de ports en multi-threading avec ThreadPoolExecutor.
    Retourne une liste de dictionnaires avec le résultat de chaque port.
    
    Args:
        ip (str): L'adresse IP de la cible.
        ports (list): Une liste d'entiers représentant les ports à scanner.
        progress_callback (callable, optionnel): Fonction appelée après chaque port scanné.
    """
    resultats = []
    
    # ThreadPoolExecutor permet de lancer des threads concurrents pour le scan réseau
    # au lieu d'un seul ouvrier qui teste les ports un par un,
    # tu as 50 ouvriers qui travaillent en même temps
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        
        # Dictionnaire liant chaque future (tâche asynchrone) au port scanné
        futures = {executor.submit(scan_tcp, ip, port): port for port in ports}
        
        # as_completed récupère le résultat d'un thread dès qu'il est fini,
        # peu importe l'ordre de lancement → barre de progression fluide en temps réel
        for future in concurrent.futures.as_completed(futures):
            try:
                res = future.result()
                resultats.append(res)
            except Exception as e:
                # Si le thread a planté, on remonte l'erreur sans bloquer les autres
                port = futures[future]
                resultats.append({
                    "port": port,
                    "statut": "erreur",
                    "service": "INCONNU",
                    "erreur": str(e)
                })
            
            if progress_callback:
                progress_callback()
    
    # Trier les résultats par numéro de port
    resultats.sort(key=lambda x: x["port"])
    return resultats