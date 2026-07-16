set export
# On utilise Bash sur Windows (car vous avez Git Bash installé)
set windows-shell := ["bash", "-uc"]
set shell := ["bash", "-uc"]

# Commande par défaut (liste les commandes)
default:
    @just --list

# ──────────────────────────────────────────────────
#  Setup & Installation
# ──────────────────────────────────────────────────

# Configurer le projet (création du venv et installation des dépendances)
setup:
    uv venv --allow-existing
    uv sync --all-extras

# ──────────────────────────────────────────────────
#  Lancement
# ──────────────────────────────────────────────────

# Lancer le scanner réseau (GUI via le fichier app.py - avec auto-élévation d'admin)
run *args:
    uv run python -m core.app {{args}}

# Lancer la version GUI (Alias de run)
gui *args:
    uv run python -m core.app {{args}}

# Lancer le CLI interactif (mode terminal guidé)
cli *args:
    uv run python -m cli.main {{args}}

# Découvrir automatiquement les hôtes actifs sur le réseau local (sortie JSON)
discover:
    uv run python -m cli.run_scan --discover

# Lancer un scan rapide automatique sur un hôte cible (ex: just scan-fast 192.168.1.1)
scan-fast target_ip:
    uv run python -m cli.run_scan --target {{target_ip}} --mode fast

# Lancer un scan complet (65535 ports) automatique sur un hôte cible (ex: just scan-full 192.168.1.1)
scan-full target_ip:
    uv run python -m cli.run_scan --target {{target_ip}} --mode full

# ──────────────────────────────────────────────────
#  Qualité du Code
# ──────────────────────────────────────────────────

# Lancer les tests unitaires
test *args:
    uv run pytest {{args}}

# Lancer les tests avec couverture détaillée
test-verbose:
    uv run pytest -v --tb=short

# Vérifier la qualité du code (linters)
lint:
    uv run ruff check core/ gui/ scanner/ model/ reporter/ cli/ tests/
    uv run mypy core/ gui/ scanner/ model/ reporter/ cli/

# Formater proprement le code
format:
    uv run yapf -ir core/ gui/ scanner/ model/ reporter/ cli/ tests/

# Vérifier le formatage sans modifier les fichiers
format-check:
    uv run yapf -dr core/ gui/ scanner/ model/ reporter/ cli/ tests/

# ──────────────────────────────────────────────────
#  Build & Release
# ──────────────────────────────────────────────────

# Compiler l'exécutable Windows (PyInstaller)
build:
    cd build_tools && build.bat

# Créer le package portable
package:
    cd build_tools && package_release.bat

# ──────────────────────────────────────────────────
#  Utilitaires
# ──────────────────────────────────────────────────

# Tester la connexion à l'API Groq
test-groq:
    uv run python tests/test_groq_standalone.py

# Nettoyer les fichiers temporaires et caches
clean:
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
    find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
    find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
    rm -f outputs/scan_result.json outputs/report.html
