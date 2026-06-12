import json
import os
from unittest.mock import patch, MagicMock

import pytest

from reporter.ai_generator import generate_ai_report


SAMPLE_SCAN = {
    "cible": "192.168.1.1",
    "date": "2026-06-06 12:00:00",
    "total_scanned": 22,
    "ports": [
        {
            "port": 22,
            "service": "SSH",
            "version": "OpenSSH/8.2",
            "label": "VULNÉRABLE",
            "cves": [{"cve_id": "CVE-2024-0001"}],
        }
    ],
}


class TestGenerateAiReport:
    def test_missing_api_key_writes_error(self, tmp_path):
        out = tmp_path / "ai_report.md"
        with patch.dict(os.environ, {}, clear=True):
            generate_ai_report(SAMPLE_SCAN, api_key=None, output_path=str(out))
        content = out.read_text(encoding="utf-8")
        assert "GROQ_API_KEY" in content

    @patch("reporter.ai_generator.urllib.request.urlopen")
    def test_successful_api_call(self, mock_urlopen, tmp_path):
        out = tmp_path / "ai_report.md"
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "choices": [{"message": {"content": "# Rapport de test\nSynthèse OK."}}]
        }).encode("utf-8")
        mock_response.__enter__ = lambda s: mock_response
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        generate_ai_report(SAMPLE_SCAN, api_key="test-key", output_path=str(out))

        content = out.read_text(encoding="utf-8")
        assert "Rapport de test" in content
        req = mock_urlopen.call_args[0][0]
        assert req.get_method() == "POST"
        assert "api.groq.com" in req.full_url

    @patch("reporter.ai_generator.urllib.request.urlopen")
    def test_ssl_context_uses_default_verification(self, mock_urlopen, tmp_path):
        out = tmp_path / "ai_report.md"
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "choices": [{"message": {"content": "OK"}}]
        }).encode("utf-8")
        mock_response.__enter__ = lambda s: mock_response
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        generate_ai_report(SAMPLE_SCAN, api_key="test-key", output_path=str(out))

        ctx = mock_urlopen.call_args[1]["context"]
        import ssl
        assert ctx.verify_mode == ssl.CERT_REQUIRED
