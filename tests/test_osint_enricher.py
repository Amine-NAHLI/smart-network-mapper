import json
import ssl
from unittest.mock import patch, MagicMock

import pytest

from scanner.osint_enricher import (
    _extract_version_number,
    _build_search_keyword,
    _parse_cve_entry,
    enrich_with_cves,
    _query_nvd,
)


class TestOsintHelpers:
    def test_extract_version_from_banner(self):
        assert _extract_version_number("Apache/2.4.58") == "2.4.58"
        assert _extract_version_number("N/A") == ""

    def test_build_search_keyword(self):
        assert _build_search_keyword("apache", "2.4.58") == "apache 2.4.58"

    def test_parse_cve_entry(self):
        raw = {
            "cve": {
                "id": "CVE-2024-1234",
                "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}
                    }]
                },
                "published": "2024-01-15T00:00:00.000",
            }
        }
        parsed = _parse_cve_entry(raw)
        assert parsed["cve_id"] == "CVE-2024-1234"
        assert parsed["cvss_score"] == 9.8
        assert parsed["severity"] == "CRITICAL"


class TestQueryNvd:
    @patch("scanner.osint_enricher.urllib.request.urlopen")
    def test_ssl_uses_certificate_verification(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({"vulnerabilities": []}).encode()
        mock_response.__enter__ = lambda s: mock_response
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        _query_nvd("apache 2.4.58")

        ctx = mock_urlopen.call_args[1]["context"]
        assert ctx.verify_mode == ssl.CERT_REQUIRED


class TestEnrichWithCves:
    @patch("scanner.osint_enricher._query_nvd")
    @patch("scanner.osint_enricher.time.sleep")
    def test_skips_ports_without_version(self, mock_sleep, mock_query):
        ports = [{"port": 80, "service": "http", "version": "N/A"}]
        result = enrich_with_cves(ports)
        assert result[80] == []
        mock_query.assert_not_called()

    @patch("scanner.osint_enricher._query_nvd")
    @patch("scanner.osint_enricher.time.sleep")
    def test_enriches_ports_with_version(self, mock_sleep, mock_query):
        mock_query.return_value = [{
            "cve": {
                "id": "CVE-2024-9999",
                "descriptions": [{"lang": "en", "value": "Desc"}],
                "metrics": {},
                "published": "2024-06-01",
            }
        }]
        ports = [{"port": 22, "service": "ssh", "version": "OpenSSH/8.2p1"}]
        result = enrich_with_cves(ports)
        assert len(result[22]) == 1
        assert result[22][0]["cve_id"] == "CVE-2024-9999"
