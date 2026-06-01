"""
Téléchargement des modèles IA (Hugging Face) — utilisé par l'exe et download_models.py.
"""
import os
from typing import Callable, Optional

from snm_paths import (
    get_model_dir,
    get_hf_cache_dir,
    fix_frozen_stdio,
    configure_hf_download_env,
)

REPO_ID = "aminenahli/smart-network-mapper-models"

MODEL_FILES = (
    "vulnerability_model.pkl",
    "quantile_transformer.pkl",
    "scaler.pkl",
    "feature_names.pkl",
)

# Fichier principal : au moins ~100 Mo si présent (évite un .pkl tronqué)
_MIN_MAIN_MODEL_BYTES = 100 * 1024 * 1024


def _file_ok(path: str, filename: str) -> bool:
    if not os.path.isfile(path):
        return False
    size = os.path.getsize(path)
    if size <= 0:
        return False
    if filename == "vulnerability_model.pkl":
        return size >= _MIN_MAIN_MODEL_BYTES
    return True


def all_models_present() -> bool:
    model_dir = get_model_dir()
    return all(
        _file_ok(os.path.join(model_dir, name), name)
        for name in MODEL_FILES
    )


def download_all_models(
    on_progress: Optional[Callable[[int, int, str, str], None]] = None,
) -> None:
    """
    Télécharge tous les modèles dans get_model_dir().

    on_progress(index, total, filename, phase) avec phase in:
      'skip', 'download', 'done'
    """
    fix_frozen_stdio()
    configure_hf_download_env()

    from huggingface_hub import hf_hub_download

    model_dir = get_model_dir()
    os.makedirs(model_dir, exist_ok=True)

    total = len(MODEL_FILES)

    for i, filename in enumerate(MODEL_FILES):
        dest = os.path.join(model_dir, filename)

        if _file_ok(dest, filename):
            if on_progress:
                on_progress(i, total, filename, "skip")
            continue

        if on_progress:
            on_progress(i, total, filename, "download")

        hf_hub_download(
            repo_id=REPO_ID,
            filename=filename,
            local_dir=model_dir,
            local_dir_use_symlinks=False,
            cache_dir=get_hf_cache_dir(),
        )

        if not _file_ok(dest, filename):
            raise OSError(
                f"Téléchargement incomplet ou invalide : {filename}\n"
                f"Vérifiez votre connexion et l'espace disque (~6 Go libres)."
            )

        if on_progress:
            on_progress(i + 1, total, filename, "done")
