import os
from core import paths as snm_paths

def test_paths():
    # Test que get_base_dir retourne un chemin valide existant
    base = snm_paths.get_base_dir()
    assert isinstance(base, str)
    assert os.path.exists(base)
    
    # Test model dir
    model_dir = snm_paths.get_model_dir()
    assert model_dir.endswith("model")
    
    # Test HF Cache dir
    hf_cache = snm_paths.get_hf_cache_dir()
    assert "hf_cache" in hf_cache
    assert os.path.exists(hf_cache)

def test_ensure_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(snm_paths, "get_base_dir", lambda: str(tmp_path))
    
    # Initialement n'existent pas
    assert not os.path.exists(tmp_path / "outputs")
    assert not os.path.exists(tmp_path / "resources")
    
    # ensure_outputs_dir
    out_dir = snm_paths.ensure_outputs_dir()
    assert os.path.exists(out_dir)
    assert out_dir.endswith("outputs")
    
    # ensure_resources_dir
    res_dir = snm_paths.ensure_resources_dir()
    assert os.path.exists(res_dir)
    assert res_dir.endswith("resources")
