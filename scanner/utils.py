import ipaddress

def parse_subnet(subnet):
    """
    Analyse une chaîne de sous-réseau CIDR et retourne une liste de toutes les adresses IP des hôtes.
    """
    try:    
        network = ipaddress.ip_network(subnet, strict=False)
        return [str(ip) for ip in network.hosts()]
        #str(ip) → 
        #convertit l'objet IP en chaîne de caractères 
        #network.hosts() → 
        #une méthode qui retourne un itérateur sur toutes les adresses IP utilisables dans le réseau (exclut l'adresse réseau et l'adresse de broadcast)
    except ValueError:
        return []
    #ValueError → 
    #si le subnet est invalide retourner une liste vide

def validate_cidr(subnet):
    """
    `ipaddress` → 
    la biblio Python spécialisée dans les adresses réseau et verifie tous les caracteristiques de l'adresse IP et du masque
    `.ip_network()` → 
    la fonction de cette librairie qui essaie de créer un objet réseau à partir d'un texte.
    `strict=False` → 
    permet d'accepter des adresses qui ne sont pas exactement le début du réseau (ex: 192.168.1.5/24 est accepté) false la tolere et la corrige et la rend comme 192.168.1.0/24
    """
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True 
    except ValueError:
        return False

