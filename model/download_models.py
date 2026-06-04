"""
Téléchargement des modèles IA depuis Hugging Face Hub (ligne de commande).
"""
import sys

try:
    from huggingface_hub import hf_hub_download  # noqa: F401 — vérifie l'installation
except ImportError:
    print("Erreur : 'huggingface_hub' n'est pas installé.")
    print("Lancez : pip install huggingface_hub")
    sys.exit(1)

from model.model_download import REPO_ID, download_all_models


def download_models():
    print("\nSmart Network Mapper — Téléchargement des modèles IA")
    print(f"Source : https://huggingface.co/{REPO_ID}")
    print("-" * 50)

    def on_progress(index, total, filename, phase):
        if phase == "skip":
            print(f"  {filename:<30} déjà présent")
        elif phase == "download":
            print(f"  Téléchargement {index + 1}/{total} : {filename} ...")
        elif phase == "done":
            print(f"  {filename:<30} terminé")

    download_all_models(on_progress=on_progress)

    print("-" * 50)
    print("Tous les modèles sont prêts.\n")


if __name__ == "__main__":
    download_models()
