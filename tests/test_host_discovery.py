import pytest
from scanner.utils import validate_cidr, parse_subnet

class TestUtils:
    # ---------------------------------------------------------
    # Tests pour validate_cidr
    # ---------------------------------------------------------
    def test_validate_cidr_valid_normal(self):
        """Tester les formats CIDR valides standard"""
        assert validate_cidr("192.168.1.0/24") is True
        assert validate_cidr("10.0.0.0/8") is True
        assert validate_cidr("172.16.0.0/16") is True

    def test_validate_cidr_edge_cases(self):
        """Tester les cas particuliers comme /32, /30, /0"""
        assert validate_cidr("192.168.1.100/32") is True
        assert validate_cidr("10.0.0.0/30") is True
        assert validate_cidr("0.0.0.0/0") is True
        
        # Le module ipaddress suppose /32 si aucun masque n'est fourni
        assert validate_cidr("192.168.1.1") is True 

    def test_validate_cidr_invalid(self):
        """Tester les chaînes complètement invalides et les IP/masques hors limites"""
        assert validate_cidr("invalid_string") is False
        assert validate_cidr("256.256.256.256/24") is False  # IP hors limites
        assert validate_cidr("192.168.1.0/33") is False      # Masque invalide
        assert validate_cidr("192.168.1.0/abc") is False     # Masque non numérique
        assert validate_cidr("") is False

    # ---------------------------------------------------------
    # Tests pour parse_subnet
    # ---------------------------------------------------------
    def test_parse_subnet_valid(self):
        """Tester que parse_subnet retourne la liste correcte d'IPs pour des CIDR standards"""
        # Les réseaux /30 ont exactement 2 hôtes utilisables
        ips = parse_subnet("192.168.1.0/30")
        assert isinstance(ips, list)
        assert len(ips) == 2
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips

    def test_parse_subnet_edge_cases(self):
        """Tester parse_subnet avec des petits sous-réseaux et des correspondances exactes"""
        # Un /32 est juste un seul hôte
        ips_32 = parse_subnet("192.168.1.100/32")
        assert len(ips_32) == 1
        assert ips_32 == ["192.168.1.100"]
        
        # Un /31 est une liaison point à point avec exactement 2 adresses (toutes deux utilisables)
        ips_31 = parse_subnet("10.0.0.0/31")
        assert len(ips_31) == 2
        assert "10.0.0.0" in ips_31
        assert "10.0.0.1" in ips_31

    def test_parse_subnet_invalid(self):
        """Tester que parse_subnet gère correctement les ValueErrors en retournant une liste vide"""
        assert parse_subnet("not_an_ip") == []
        assert parse_subnet("256.256.256.256/100") == []
        assert parse_subnet("") == []
