import os
from reporter.html_generator import generate_html_report

def test_generate_html_report(tmp_path):
    output_path = tmp_path / "report.html"
    scan_data = {
        "cible": "192.168.1.1",
        "date": "2026-07-05",
        "total_scanned": 100,
        "ports": [
            {
                "port": 80, 
                "statut": "ouvert", 
                "service": "http", 
                "vulnerable": 0, 
                "confidence": 0.9, 
                "label": "SAFE", 
                "cves": []
            },
            {
                "port": 443, 
                "statut": "ouvert", 
                "service": "https", 
                "vulnerable": 1, 
                "confidence": 0.8, 
                "label": "VULN", 
                "cves": [{
                    "cvss_score": 9.5, 
                    "severity": "CRITICAL", 
                    "cve_id": "CVE-2023-123", 
                    "description": "Test vulnerability description",
                    "url": "http://test",
                    "published": "2023-01-01"
                }]
            }
        ]
    }
    
    result_path = generate_html_report(scan_data, output_path=str(output_path))
    assert result_path == str(output_path)
    assert os.path.exists(output_path)
    
    content = output_path.read_text(encoding="utf-8")
    
    # Vérification des informations de base injectées
    assert "192.168.1.1" in content
    assert "CVE-2023-123" in content
    assert "Test vulnerability description" in content
    
    # Vérification des statistiques générées (1 sûr sur 2 ouverts -> 50%)
    assert "50%" in content
    assert "2026-07-05" in content

def test_generate_html_report_zero_open_ports(tmp_path):
    # Test de robustesse (division par zéro dans HTML generator)
    output_path = tmp_path / "report_safe.html"
    scan_data = {
        "cible": "192.168.1.2",
        "date": "2026-07-05",
        "total_scanned": 100,
        "ports": []  # Aucun port ouvert
    }
    generate_html_report(scan_data, output_path=str(output_path))
    content = output_path.read_text(encoding="utf-8")
    
    assert "100%" in content  # Si aucun port ouvert, c'est considéré comme 100% sûr
