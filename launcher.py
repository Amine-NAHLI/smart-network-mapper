import ctypes
import sys
import os
import subprocess

# ── 1. Vérifier si on est admin ──────────────────────────────────────
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

# ── 2. Se relancer en admin si nécessaire ────────────────────────────
def relaunch_as_admin():
    # Récupère le chemin de l'exe (ou du script Python)
    if getattr(sys, 'frozen', False):
        # On est dans un .exe PyInstaller
        executable = sys.executable
        params = ""
    else:
        # On est en mode développement Python
        executable = sys.executable
        params = f'"{os.path.abspath(__file__)}"'

    # Déclenche le popup UAC Windows
    ctypes.windll.shell32.ShellExecuteW(
        None,       # handle fenêtre parent
        "runas",    # demande élévation admin
        executable, # programme à relancer
        params,     # arguments
        None,       # dossier de travail
        1           # SW_SHOWNORMAL
    )
    sys.exit(0)  # Ferme le processus non-admin

# ── 3. Trouver le dossier racine du projet ───────────────────────────
def get_base_dir():
    if getattr(sys, 'frozen', False):
        # En mode .exe : dossier où se trouve le .exe
        return os.path.dirname(sys.executable)
    else:
        # En mode dev : dossier du launcher.py
        return os.path.dirname(os.path.abspath(__file__))

# ── 4. Vérifier si les modèles IA existent ───────────────────────────
def models_exist(base_dir):
    model_path = os.path.join(base_dir, "model", "vulnerability_model.pkl")
    return os.path.exists(model_path)

# ── 5. Lancer le bon fichier ─────────────────────────────────────────
def launch(base_dir):
    if models_exist(base_dir):
        # Modèles présents → lancer l'app principale
        target = os.path.join(base_dir, "app.py")
        print("[SNM] Modèles trouvés → lancement de app.py")
    else:
        # Modèles manquants → lancer le downloader
        target = os.path.join(base_dir, "model_downloader_gui.py")
        print("[SNM] Modèles manquants → lancement du downloader")

    subprocess.Popen([sys.executable, target])

# ── POINT D'ENTRÉE ───────────────────────────────────────────────────
if __name__ == "__main__":
    if not is_admin():
        print("[SNM] Pas admin → demande élévation UAC...")
        relaunch_as_admin()
    else:
        print("[SNM] Admin confirmé ✓")
        base = get_base_dir()
        launch(base)