"""
snm_env.py
----------
Chargement centralisé des variables d'environnement depuis .env
(sans dépendance python-dotenv).
"""

import os


def load_dotenv(base_dir: str | None = None) -> None:
    """Charge le fichier .env du projet dans os.environ (sans écraser l'existant)."""
    if base_dir is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    env_path = os.path.join(base_dir, ".env")
    if not os.path.isfile(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), val.strip().strip("'\""))
