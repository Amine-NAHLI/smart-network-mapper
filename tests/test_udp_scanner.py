import socket
from unittest.mock import patch, MagicMock

import pytest

from scanner.port_scanner import scan_udp, scan_udp_ports, TOP_UDP_PORTS, get_service


class TestGetServiceUdp:
    def test_dns_port(self):
        assert get_service(53, "udp") == "DOMAIN"


class TestScanUdp:
    @patch("scanner.port_scanner.socket.socket")
    def test_open_port_with_response(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (b"DNS response data", ("192.168.1.1", 53))
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        result = scan_udp("192.168.1.1", 53)

        assert result["protocole"] == "UDP"
        assert result["statut"] == "ouvert"
        assert result["port"] == 53

    @patch("scanner.port_scanner.socket.socket")
    def test_closed_or_filtered_on_timeout(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = socket.timeout()
        mock_socket_class.return_value.__enter__.return_value = mock_sock

        result = scan_udp("192.168.1.1", 161)

        assert result["statut"] == "fermé/filtré"
        assert result["protocole"] == "UDP"


class TestScanUdpPorts:
    @patch("scanner.port_scanner.scan_udp")
    def test_returns_sorted_results(self, mock_scan_udp):
        mock_scan_udp.side_effect = lambda ip, port: {
            "port": port, "protocole": "UDP", "statut": "fermé/filtré",
            "service": "TEST", "banner": "", "version": "N/A",
        }
        results = scan_udp_ports("10.0.0.1", [161, 53])
        assert len(results) == 2
        assert results[0]["port"] <= results[1]["port"]

    def test_top_udp_ports_defined(self):
        assert 53 in TOP_UDP_PORTS
        assert 161 in TOP_UDP_PORTS
