"""
Upload du ZIP Windows portable sur Hugging Face pour le bouton de telechargement du site doc.

Usage (apres package_release.bat et creation du ZIP) :
  python upload_windows_release.py

Cree le depot : https://huggingface.co/aminenahli/snm-windows-portable
"""
import os
import sys

REPO_ID = "aminenahli/snm-windows-portable"
ZIP_NAME = "SNM_Windows_Portable_Complet.zip"

# Chemins possibles du ZIP
CANDIDATES = [
    os.path.join(os.path.dirname(__file__), "release", ZIP_NAME),
    os.path.join(os.path.dirname(__file__), "release", "SNM_Windows_Portable", ZIP_NAME),
]


def find_zip():
    for path in CANDIDATES:
        if os.path.isfile(path) and os.path.getsize(path) > 100_000_000:
            return path
    return None


def main():
    zip_path = find_zip()
    if not zip_path:
        print("ZIP introuvable. Creez-le d'abord :")
        print("  cd release")
        print(f"  tar -a -c -f {ZIP_NAME} SNM_Windows_Portable")
        sys.exit(1)

    size_gb = os.path.getsize(zip_path) / (1024 ** 3)
    print(f"Fichier : {zip_path}")
    print(f"Taille  : {size_gb:.2f} Go")
    print(f"Depot   : https://huggingface.co/{REPO_ID}")
    print("Upload en cours (peut prendre 30-60 min)...")

    try:
        from huggingface_hub import HfApi
    except ImportError:
        print("pip install huggingface_hub")
        sys.exit(1)

    api = HfApi()
    try:
        api.create_repo(repo_id=REPO_ID, repo_type="model", exist_ok=True)
    except Exception as e:
        print(f"Note repo : {e}")

    api.upload_file(
        path_or_fileobj=zip_path,
        path_in_repo=ZIP_NAME,
        repo_id=REPO_ID,
        repo_type="model",
    )

    url = f"https://huggingface.co/{REPO_ID}/resolve/main/{ZIP_NAME}"
    print()
    print("Upload termine.")
    print(f"Lien direct : {url}")
    print()
    print("Verifiez que snm-docs/src/config/downloads.js utilise cette URL,")
    print("puis : cd snm-docs && npm run build && npm run deploy")


if __name__ == "__main__":
    main()
