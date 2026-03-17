import pytest
from scanner.utils import validate_cidr, parse_subnet

class TestUtils:
    # ---------------------------------------------------------
    # Tests for validate_cidr
    # ---------------------------------------------------------
    def test_validate_cidr_valid_normal(self):
        """Test standard valid CIDR formats"""
        assert validate_cidr("192.168.1.0/24") is True
        assert validate_cidr("10.0.0.0/8") is True
        assert validate_cidr("172.16.0.0/16") is True

    def test_validate_cidr_edge_cases(self):
        """Test edge cases like /32, /30, /0"""
        assert validate_cidr("192.168.1.100/32") is True
        assert validate_cidr("10.0.0.0/30") is True
        assert validate_cidr("0.0.0.0/0") is True
        
        # ipaddress module assumes /32 if no mask is provided
        assert validate_cidr("192.168.1.1") is True 

    def test_validate_cidr_invalid(self):
        """Test completely invalid strings and out-of-bounds IPs/masks"""
        assert validate_cidr("invalid_string") is False
        assert validate_cidr("256.256.256.256/24") is False  # Out of bounds IP
        assert validate_cidr("192.168.1.0/33") is False      # Invalid mask
        assert validate_cidr("192.168.1.0/abc") is False     # Non-numeric mask
        assert validate_cidr("") is False

    # ---------------------------------------------------------
    # Tests for parse_subnet
    # ---------------------------------------------------------
    def test_parse_subnet_valid(self):
        """Test that parse_subnet returns the correct list of IPs for standard CIDRs"""
        # /30 networks have exactly 2 usable hosts
        ips = parse_subnet("192.168.1.0/30")
        assert isinstance(ips, list)
        assert len(ips) == 2
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips

    def test_parse_subnet_edge_cases(self):
        """Test parse_subnet with small and exact match subnets"""
        # A /32 is just a single host
        ips_32 = parse_subnet("192.168.1.100/32")
        assert len(ips_32) == 1
        assert ips_32 == ["192.168.1.100"]
        
        # A /31 is a point-to-point link with exactly 2 addresses (both usable)
        ips_31 = parse_subnet("10.0.0.0/31")
        assert len(ips_31) == 2
        assert "10.0.0.0" in ips_31
        assert "10.0.0.1" in ips_31

    def test_parse_subnet_invalid(self):
        """Test parse_subnet handles ValueErrors correctly by returning an empty list"""
        assert parse_subnet("not_an_ip") == []
        assert parse_subnet("256.256.256.256/100") == []
        assert parse_subnet("") == []
