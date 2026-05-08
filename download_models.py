"""
Téléchargement des modèles IA depuis Hugging Face Hub.
À exécuter une seule fois après le clonage du projet.
"""
import os
import sys

try:
    # pyrefly: ignore [missing-import]
    from huggingface_hub import hf_hub_download
except ImportError:
    print("❌ Erreur : 'huggingface_hub' n'est pas installé.")
    print("Veuillez lancer : pip install huggingface_hub")
    sys.exit(1)

REPO_ID = "aminenahli/smart-network-mapper-models"
MODEL_DIR = os.path.join(os.path.dirname(__file__), "model")
FILES = [
    "vulnerability_model.pkl",
    "quantile_transformer.pkl",
    "scaler.pkl",
    "feature_names.pkl",
]

def download_models():
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR)
        
    print("\n🛰️  Smart Network Mapper — Téléchargement des modèles IA")
    print(f"🔗 Source : https://huggingface.co/{REPO_ID}")
    print("-" * 50)
    
    for filename in FILES:
        dest = os.path.join(MODEL_DIR, filename)
        if os.path.exists(dest):
            print(f"✅ {filename:<25} | Déjà présent, skip.")
            continue
            
        print(f"⬇️  Téléchargement de {filename:<22}...", end="", flush=True)
        try:
            hf_hub_download(
                repo_id=REPO_ID, 
                filename=filename, 
                local_dir=MODEL_DIR,
                local_dir_use_symlinks=False
            )
            print(" [ TERMINÉ ]")
        except Exception as e:
            print(f" [ ERREUR : {e} ]")
            
    print("-" * 50)
    print("🎉 Tous les modèles sont prêts !\n")

if __name__ == "__main__":
    download_models()
