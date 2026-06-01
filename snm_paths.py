"""
Chemins de l'application (dev Python ou exe PyInstaller).
Les modèles .pkl (~5 Go) restent dans {base_dir}/model/ à côté de l'exe.
"""
import os
import sys

_stdio_devnull = None


def fix_frozen_stdio() -> None:
    """
    En exe PyInstaller (console=False), stdout/stderr valent None.
    huggingface_hub / tqdm appellent .write() dessus → crash.
    """
    global _stdio_devnull
    if not getattr(sys, "frozen", False):
        return
    if _stdio_devnull is None:
        _stdio_devnull = open(os.devnull, "w", encoding="utf-8", errors="replace")
    if sys.stdout is None:
        sys.stdout = _stdio_devnull
    if sys.stderr is None:
        sys.stderr = _stdio_devnull


def get_hf_cache_dir() -> str:
    """
    Cache Hugging Face hors du dossier dist/ (évite de bloquer le rebuild PyInstaller).
    Windows : %LOCALAPPDATA%\\SmartNetworkMapper\\hf_cache
    """
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    path = os.path.join(base, "SmartNetworkMapper", "hf_cache")
    os.makedirs(path, exist_ok=True)
    return path


def configure_hf_download_env() -> None:
    """Cache HF + désactivation des barres tqdm (obligatoire en exe sans console)."""
    cache = get_hf_cache_dir()
    os.environ["HF_HOME"] = cache
    os.environ["HUGGINGFACE_HUB_CACHE"] = os.path.join(cache, "hub")
    os.makedirs(os.environ["HUGGINGFACE_HUB_CACHE"], exist_ok=True)
    os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    os.environ["TQDM_DISABLE"] = "1"


def get_base_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def get_model_dir() -> str:
    return os.path.join(get_base_dir(), "model")


def get_outputs_dir() -> str:
    return os.path.join(get_base_dir(), "outputs")


def ensure_outputs_dir() -> str:
    path = get_outputs_dir()
    os.makedirs(path, exist_ok=True)
    return path
