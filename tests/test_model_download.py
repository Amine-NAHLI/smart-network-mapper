import os
import pytest
from model import model_download

def test_file_ok(tmp_path):
    f = tmp_path / "test.txt"
    # Le fichier n'existe pas
    assert model_download._file_ok(str(f), "test.txt") is False
    
    # Fichier vide
    f.touch()
    assert model_download._file_ok(str(f), "test.txt") is False
    
    # Fichier non vide normal
    f.write_text("hello")
    assert model_download._file_ok(str(f), "test.txt") is True

def test_file_ok_main_model(tmp_path):
    f = tmp_path / "vulnerability_model.pkl"
    # Trop petit
    f.write_text("small")
    assert model_download._file_ok(str(f), "vulnerability_model.pkl") is False
    
    # Assez grand (> 100 Mo) - On crée un fichier sparse pour la vitesse
    with open(f, "wb") as file:
        file.seek(101 * 1024 * 1024)
        file.write(b"\0")
    assert model_download._file_ok(str(f), "vulnerability_model.pkl") is True

def test_download_all_models_mocked(monkeypatch, tmp_path):
    # Mock get_base_dir pour que get_model_dir pointe vers le dossier temporaire
    import snm_paths
    monkeypatch.setattr(snm_paths, "get_base_dir", lambda: str(tmp_path))
    
    # Mock la fonction hf_hub_download pour créer de faux fichiers
    def mock_download(repo_id, filename, local_dir, **kwargs):
        path = os.path.join(local_dir, filename)
        with open(path, "wb") as f:
            if filename == "vulnerability_model.pkl":
                f.seek(101 * 1024 * 1024) # Fichier sparse > 100 Mo
                f.write(b"\0")
            else:
                f.write(b"dummy_data")
                
    import huggingface_hub
    monkeypatch.setattr(huggingface_hub, "hf_hub_download", mock_download)
    
    progress_calls = []
    def on_prog(idx, total, fname, phase):
        progress_calls.append(phase)
        
    # Premier passage : ça doit télécharger
    model_download.download_all_models(on_progress=on_prog)
    assert "download" in progress_calls
    assert "done" in progress_calls
    
    # Deuxième passage : ça doit skipper (les fichiers sont là et valides)
    progress_calls.clear()
    model_download.download_all_models(on_progress=on_prog)
    assert "skip" in progress_calls
    assert "download" not in progress_calls
