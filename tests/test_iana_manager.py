import json
import os
import time
import unittest
from unittest.mock import patch, MagicMock

from scanner.iana_manager import (
    get_service_name,
    get_all_known_ports,
    parse_iana_csv,
    save_iana_cache,
    load_iana_cache,
    init_iana_database,
    STATIC_SERVICE_NAMES,
)


class TestIanaManager(unittest.TestCase):
    """Tests unitaires pour le module iana_manager."""

    def test_iana_download(self):
        """test_iana_download() — vérifie le parsing du CSV IANA."""
        sample_csv = (
            "Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,Registration Date,Modification Date,Reference,Service Code,Known Unauthorized Uses,Assignment Notes\n"
            "http,80,tcp,World Wide Web HTTP,,,,,,\n"
            "ssh,22,tcp,Secure Shell Protocol,,,,,,\n"
        )
        parsed = parse_iana_csv(sample_csv)
        self.assertIn("ports", parsed)
        self.assertIn("80/tcp", parsed["ports"])
        self.assertEqual(parsed["ports"]["80/tcp"]["service"], "http")
        self.assertEqual(parsed["ports"]["22/tcp"]["service"], "ssh")

    def test_iana_cache(self):
        """test_iana_cache() — vérifie que le cache JSON est bien créé et relu."""
        test_cache_path = os.path.join("resources", "test_iana_cache.json")
        sample_data = {
            "metadata": {
                "timestamp": int(time.time()),
                "last_updated": "2026-06-28T00:00:00",
            },
            "ports": {
                "80/tcp": {"service": "http", "description": "HTTP service"}
            },
            "services": {"http": [80]},
        }
        try:
            save_iana_cache(sample_data, test_cache_path)
            self.assertTrue(os.path.exists(test_cache_path))

            loaded = load_iana_cache(test_cache_path)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["ports"]["80/tcp"]["service"], "http")
        finally:
            if os.path.exists(test_cache_path):
                os.remove(test_cache_path)

    @patch("scanner.iana_manager.download_iana_csv")
    @patch("scanner.iana_manager.load_iana_cache", return_value=None)
    def test_iana_fallback(self, mock_load, mock_download):
        """test_iana_fallback() — vérifie que le fallback statique fonctionne si l'API et le cache échouent."""
        mock_download.side_effect = Exception("Network offline")
        
        # Initialiser sans cache ni réseau
        with patch("scanner.iana_manager._iana_cache", None):
            init_iana_database(force_download=True)
            # Doit utiliser le fallback statique
            service = get_service_name(80, "tcp")
            self.assertEqual(service, "http")

    def test_get_service_name(self):
        """test_get_service_name() — vérifie la résolution à 3 niveaux (IANA -> Statique -> unknown-service-{port})."""
        mock_cache = {
            "ports": {
                "1234/tcp": {"service": "custom-app", "description": "Custom App"}
            }
        }
        with patch("scanner.iana_manager._get_active_cache", return_value=mock_cache):
            # Tier 1: IANA Cache
            self.assertEqual(get_service_name(1234, "tcp"), "custom-app")

            # Tier 2: Static Fallback (ex: port 80 quand non présent dans mock_cache)
            self.assertEqual(get_service_name(80, "tcp"), "http")

            # Tier 3: Unknown
            self.assertEqual(get_service_name(59999, "tcp"), "unknown-service-59999")


if __name__ == "__main__":
    unittest.main()
