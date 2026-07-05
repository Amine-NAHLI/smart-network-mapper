import os
import pytest
from gui import db
import snm_paths

def test_db_operations(tmp_path, monkeypatch):
    # Mock le répertoire de base pour ne pas polluer le vrai dossier
    monkeypatch.setattr(snm_paths, "get_base_dir", lambda: str(tmp_path))
    
    # Initialisation
    db.init_db()
    assert os.path.exists(os.path.join(tmp_path, "outputs", "history.db"))
    
    # Test d'insertion
    scan_id = db.insert_scan("192.168.1.1", "2026-07-05", 10.5, 2, 1, 100, "/path/json")
    assert scan_id == 1
    
    # Test récupération de tous les scans
    scans = db.get_all_scans()
    assert len(scans) == 1
    assert scans[0]["target"] == "192.168.1.1"
    assert scans[0]["open_ports"] == 2
    
    # Test récupération par ID
    scan = db.get_scan_by_id(scan_id)
    assert scan is not None
    assert scan["vuln_ports"] == 1
    
    # Test suppression
    db.delete_scan(scan_id)
    assert len(db.get_all_scans()) == 0
    
    # Test suppression totale
    db.insert_scan("1.1.1.1", "today", 1, 1, 0, 10, "")
    db.delete_all_scans()
    assert len(db.get_all_scans()) == 0
