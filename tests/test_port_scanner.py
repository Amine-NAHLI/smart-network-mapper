import unittest
from unittest.mock import patch, MagicMock
from scanner.port_scanner import get_service, scan_tcp, scan_ports

class TestGetService(unittest.TestCase):
    """Tests pour la fonction get_service"""

    def test_port_connu(self):
        # Le port 80 doit retourner HTTP
        result = get_service(80)
        self.assertEqual(result, "HTTP")

    def test_port_inconnu(self):
        # Un port non référencé doit retourner INCONNU
        result = get_service(19999)
        self.assertEqual(result, "INCONNU")

class TestScanTcp(unittest.TestCase):
    """Tests pour la fonction scan_tcp"""

    @patch("scanner.port_scanner.socket.socket")
    def test_port_ouvert(self, mock_socket_class):
        # Simuler connect_ex qui retourne 0 → port ouvert
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 0
        mock_socket_class.return_value.__enter__.return_value = mock_socket

        result = scan_tcp("192.168.1.1", 80)

        self.assertEqual(result["port"], 80)
        self.assertEqual(result["statut"], "ouvert")
        self.assertIn("service", result)

    @patch("scanner.port_scanner.socket.socket")
    def test_port_ferme(self, mock_socket_class):
        # Simuler connect_ex qui retourne 1 → port fermé
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 1
        mock_socket_class.return_value.__enter__.return_value = mock_socket

        result = scan_tcp("192.168.1.1", 9999)

        self.assertEqual(result["port"], 9999)
        self.assertEqual(result["statut"], "fermé")

    @patch("scanner.port_scanner.socket.socket")
    def test_exception_retourne_erreur(self, mock_socket_class):
        # Simuler une exception réseau → doit retourner statut erreur sans planter
        mock_socket_class.side_effect = Exception("Erreur réseau simulée")

        result = scan_tcp("192.168.1.1", 80)

        self.assertEqual(result["statut"], "erreur")
        self.assertIn("erreur", result)

class TestScanPorts(unittest.TestCase):
    """Tests pour la fonction scan_ports"""

    @patch("scanner.port_scanner.scan_tcp")
    def test_retourne_liste(self, mock_scan_tcp):
        # Simuler scan_tcp pour chaque port
        mock_scan_tcp.side_effect = lambda ip, port: {
            "port": port, "statut": "fermé", "service": "INCONNU"
        }
        result = scan_ports("192.168.1.1", [80, 443])
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)

    @patch("scanner.port_scanner.scan_tcp")
    def test_trie_par_port(self, mock_scan_tcp):
        # Vérifier que les résultats sont triés par numéro de port
        mock_scan_tcp.side_effect = lambda ip, port: {
            "port": port, "statut": "fermé", "service": "INCONNU"
        }
        result = scan_ports("192.168.1.1", [443, 80, 22])
        ports = [r["port"] for r in result]
        self.assertEqual(ports, sorted(ports))

    @patch("scanner.port_scanner.scan_tcp")
    def test_progress_callback_appele(self, mock_scan_tcp):
        # Vérifier que le callback est appelé pour chaque port
        mock_scan_tcp.side_effect = lambda ip, port: {
            "port": port, "statut": "ouvert", "service": "HTTP"
        }
        compteur = {"valeur": 0}

        def callback():
            compteur["valeur"] += 1

        scan_ports("192.168.1.1", [80, 443, 22], progress_callback=callback)
        self.assertEqual(compteur["valeur"], 3)

if __name__ == "__main__":
    unittest.main()
