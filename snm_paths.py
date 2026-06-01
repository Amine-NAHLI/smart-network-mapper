"""
Chemins de l'application (dev Python ou exe PyInstaller).
Les modèles .pkl (~5 Go) restent dans {base_dir}/model/ à côté de l'exe.
"""
import os
import sys


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
