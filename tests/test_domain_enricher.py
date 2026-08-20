"""
tests/test_domain_enricher.py
-----------------------------
Tests unitaires pour le module de reconnaissance OSINT / Domaine.
"""

from unittest.mock import patch, MagicMock
import json
import pytest

from scanner.domain_enricher import (
    get_dns_records,
    check_security_headers,
    get_rdap_whois,
    enrich_domain_profile
)


class TestDomainEnricher:
    @patch("scanner.domain_enricher.socket.gethostbyname_ex")
    def test_get_dns_records_success(self, mock_gethost):
        mock_gethost.return_value = ("example.com", ["www.example.com"], ["93.184.216.34"])
        res = get_dns_records("example.com")
        assert res["canonical_name"] == "example.com"
        assert res["ip_addresses"] == ["93.184.216.34"]
        assert res["error"] is None

    @patch("scanner.domain_enricher.urllib.request.urlopen")
    def test_check_security_headers_grades(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.info.return_value = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin"
        }
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        res = check_security_headers("https://secure.example.com")
        assert res["security_grade"] == "A+"
        assert len(res["missing_headers"]) == 0
        assert res["status_code"] == 200

    @patch("scanner.domain_enricher.urllib.request.urlopen")
    def test_get_rdap_whois_success(self, mock_urlopen):
        mock_resp = MagicMock()
        rdap_payload = {
            "name": "TEST-NET",
            "country": "US",
            "status": ["active"],
            "entities": [{
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", "Test Organization LLC"]
                ]]
            }]
        }
        mock_resp.read.return_value = json.dumps(rdap_payload).encode("utf-8")
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        res = get_rdap_whois("8.8.8.8")
        assert res["network_name"] == "TEST-NET"
        assert res["country"] == "US"
        assert res["organization"] == "Test Organization LLC"

    @patch("scanner.domain_enricher.get_dns_records")
    @patch("scanner.domain_enricher.check_security_headers")
    @patch("scanner.domain_enricher.get_rdap_whois")
    def test_enrich_domain_profile_aggregator(self, mock_rdap, mock_headers, mock_dns):
        mock_dns.return_value = {"ip_addresses": ["1.1.1.1"]}
        mock_headers.return_value = {"security_grade": "A"}
        mock_rdap.return_value = {"country": "US"}

        profile = enrich_domain_profile("cloudflare.com")
        assert profile["target"] == "cloudflare.com"
        assert "dns" in profile
        assert "security_headers" in profile
        assert "whois_rdap" in profile
