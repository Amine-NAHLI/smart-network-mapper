import socket
import concurrent.futures

#recuperer le nom du service
def get_service(port: int) -> str:
    try:
        #on entre dans les argument le numero de port et le protocole (tcp)
        #C:\Windows\System32\drivers\etc\services
        service = socket.getservbyport(port, "tcp")
        return service.upper()
    except OSError:
        return "INCONNU"

def scan_tcp(ip: str, port: int) -> dict:
    """
    Teste si un port TCP est ouvert sur une IP donnee
    """
    try: 
        # Création d'un socket IPv4 (AF_INET=IPV4) de type TCP (SOCK_STREAM=TCP)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0) 
            # connect_ex renvoie 0 si la connexion réussit (port ouvert), sinon un code d'erreur
            # on n'utilise pas connect() car il lève une exception si le port est fermé et cela veut dir que si un port est fermer le prog va s'arreter
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
        return {
            "port": port,
            "statut": "erreur",
            "service": "INCONNU",
            "erreur": str(e)
        }

def scan_ports(ip: str, ports: list, progress_callback=None) -> list:
    """
    Scanne une liste de ports en multi-threading avec ThreadPoolExecutor
    Retourne une liste de dictionnaires avec le résultat de chaque port
    
    callback est une fonction qui sera appelée après chaque port scanné c'est pour la barre de progression c'est juste pour le style pas un truc obligatoire
    """
    resultats = []
    
     
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        
        #appeler la fonction scan_tcp pour chaque port et chaque fonction est appeler par un thread different 
        futures = {executor.submit(scan_tcp, ip, port): port for port in ports}
        
        # as_completed récupère le résultat d'un thread dès qu'il est fini peut importe l'ordre 
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
    
    resultats.sort(key=lambda x: x["port"])
    return resultats