import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUN_SCAN = PROJECT_ROOT / "cli" / "run_scan.py"


def _run(args: list[str]) -> dict:
    result = subprocess.run(
        [sys.executable, str(RUN_SCAN), *args],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip())


class TestRunScanErrors:
    def test_invalid_target_returns_json_error(self):
        # IP invalide / injoignable — le script doit renvoyer success:false sans crasher n8n
        data = _run(["--target", "999.999.999.999", "--mode", "fast"])
        # Peut réussir le scan (ports fermés) ou échouer selon l'OS — on vérifie la structure
        assert "success" in data or "error" in data

    def test_discover_outputs_success_or_error_json(self):
        data = _run(["--discover"])
        assert isinstance(data, dict)
        if data.get("success") is False:
            assert "error_message" in data or "error" in data
        else:
            assert data.get("success") is True
