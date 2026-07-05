"""
scanner/constants.py
--------------------
Constantes relatives au scan réseau (ports, protocoles, timeouts, etc).
Centralise les configurations pour éviter les duplications entre CLI et GUI.
"""

# Ports TCP les plus critiques et fréquents
TOP_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135,
    139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090
]

# Ports UDP les plus critiques et fréquents
TOP_UDP_PORTS = [
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900, 5353
]

# Ports UDP étendus pour le mode FULL
EXTENDED_UDP_PORTS = [
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1194, 1900, 4500, 5060, 5353
]
