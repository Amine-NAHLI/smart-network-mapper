# Récapitulatif du Projet : Restructuration GUI, Historique SQLite & Clean-up Racine

Ce document résume l'ensemble des travaux d'architecture, de persistance, de build et de rangement effectués sur l'application **Smart Network Mapper (SNM)**.

---

## 📁 1. Division Modulaire de l'Interface Graphique (dossier `gui/`)

L'ancienne architecture reposait sur un unique fichier géant `app.py` de plus de **1 370 lignes**, ce qui rendait la maintenance difficile et risquait de poser des problèmes pour la soutenance. Nous l'avons découpé en plusieurs modules réutilisables et spécialisés :

### Fichiers de configuration & utilitaires
*   [`gui/constants.py`](file:///d:/PFA_3/smart-network-mapper/gui/constants.py) : Contient l'ensemble du système de design (palettes de couleurs cyberpunk, polices, tailles de fenêtres) et les listes de ports.
*   [`gui/db.py`](file:///d:/PFA_3/smart-network-mapper/gui/db.py) : Gère la persistance de l'historique de scan avec une base de données locale **SQLite** (`outputs/history.db`).

### Modules de pages (dossier `gui/pages/`)
*   [`gui/pages/dashboard.py`](file:///d:/PFA_3/smart-network-mapper/gui/pages/dashboard.py) : Affiche la synthèse globale du dernier scan (cartes statistiques, graphique de répartition des vulnérabilités, tableau des ports critiques).
*   [`gui/pages/new_scan.py`](file:///d:/PFA_3/smart-network-mapper/gui/pages/new_scan.py) : Gère la configuration du CIDR, la découverte d'hôtes actifs par Ping TCP/ARP, le scan multi-threadé avec prédiction IA de vulnérabilités, et l'insertion en base SQLite.
*   [`gui/pages/results.py`](file:///d:/PFA_3/smart-network-mapper/gui/pages/results.py) : Affiche le tableau des ports trouvés avec filtres de recherche en temps réel, export JSON et affichage du rapport HTML.
*   [`gui/pages/history.py`](file:///d:/PFA_3/smart-network-mapper/gui/pages/history.py) : **Nouvelle page** qui affiche l'historique complet des scans enregistrés. Permet de charger un scan passé, de le supprimer ou de vider la base de données.
*   [`gui/pages/about.py`](file:///d:/PFA_3/smart-network-mapper/gui/pages/about.py) : Page de présentation du projet avec des animations canvas graphiques (cyberpunk grid scroll, scanline, etc.).

### Point d'entrée de l'application
*   [`app.py`](file:///d:/PFA_3/smart-network-mapper/app.py) : Allégé à seulement ~200 lignes, il n'a plus que le rôle de squelette d'application (initialisation de la fenêtre principale CustomTkinter, barre de navigation latérale, instanciation et routage des pages, initialisation SQLite).

---

## 💾 2. Intégration de la Base de Données SQLite pour l'Historique

Nous avons ajouté un historique persistant local pour que les utilisateurs puissent recharger leurs scans passés :
*   **Initialisation** : Au démarrage, la base de données est créée et configurée en mode **WAL (Write-Ahead Logging)** pour garantir des accès rapides et concurrents.
*   **Enregistrement** : Dès qu'un scan se termine sur la page `New Scan`, un résumé contenant la cible, la date, la durée, le nombre de ports ouverts et vulnérables est enregistré dans la table SQLite `scans`.
*   **Rechargement** : Le bouton **[ LOAD SCAN ]** de la page `History` lit le chemin du rapport JSON sauvegardé sur le disque, l'injecte dans le contexte partagé de l'application, et redirige l'utilisateur vers la page `Results`.

---

## 🚀 3. Automatisation du Build & Hébergement sur Hugging Face

Afin de livrer l'application finale pour la soutenance ou pour les utilisateurs :
1.  **Compilation** : Création de l'exécutable autonome `SNM.exe` via PyInstaller.
2.  **Packaging Complet** : Intégration du modèle IA volumineux (~5.1 Go) dans le dossier de release.
3.  **Compression ZIP** : Utilisation de la commande système `tar` pour contourner la limite de 2 Go des outils de compression standard de Windows.
4.  **Hébergement HF** : Téléversement du ZIP final de 5.5 Go sur le modèle de dépôt Hugging Face pour permettre le téléchargement direct.
5.  **Documentation** : Compilation et déploiement du site de documentation React sur GitHub Pages (`snm-docs`), configuré pour rediriger le bouton de téléchargement vers le lien Hugging Face.

---

## 🧹 4. Restructuration Finale et Rangement du Dossier Racine

Pour rendre le dépôt propre, structuré et professionnel, les fichiers à la racine ont été rangés dans des sous-dossiers spécifiques avec correction de tous les chemins et dépendances d'imports :

### Nouvelle structure de dossiers
*   **`cli/`** : Contient l'ancienne interface console (`main.py` déplacé en `cli/main.py`).
*   **`build_tools/`** : Regroupe les outils de build et de packaging de l'exécutable :
    *   `build.bat` (déplacé)
    *   `build.spec` (déplacé)
    *   `package_release.bat` (déplacé)
    *   `upload_windows_release.py` (déplacé)
    *   `pyi_rth_snm_stdio.py` (déplacé, runtime-hook PyInstaller)
*   **`model/`** : Regroupe toute la logique et les scripts liés aux modèles d'IA :
    *   `predictor.py` (existant)
    *   `model_download.py` (déplacé)
    *   `model_downloader_gui.py` (déplacé)
    *   `download_models.py` (déplacé)

### Ajustement des chemins & scripts
*   Les scripts `build.bat` et `package_release.bat` ont été modifiés pour remonter d'un niveau au début (`cd /d "%~dp0\.."`) afin de continuer à exécuter les actions depuis la racine du projet.
*   Le fichier `build.spec` a été adapté pour calculer `_base_dir` à la racine et inclure les imports cachés préfixés par `model.`.
*   Le script `upload_windows_release.py` a été adapté pour localiser le ZIP dans le dossier `../release/`.
*   Le point d'entrée principal [`launcher.py`](file:///d:/PFA_3/smart-network-mapper/launcher.py) et les scripts de téléchargement ont été mis à jour pour importer les modules du sous-dossier `model/` (ex. `from model.model_download import ...`).

---

## 🛠️ 5. Procédure de Rebuild (Nouvelle Structure)

Puisque tous les outils de build et de release ont été déplacés dans `build_tools/`, voici les nouvelles commandes pour compiler et packager votre application :

### A. Compiler l'exécutable (sans console)
Dans le terminal (à la racine du projet) :
```cmd
.\build_tools\build.bat
```
*Cette commande installe les dépendances, nettoie les anciens dossiers temporaires, et compile l'application propre dans `dist/SNM/`.*

### B. Créer le package portable COMPLET (avec modèles d'IA)
Dans le terminal :
```cmd
.\build_tools\package_release.bat
```
*Cette commande copie les fichiers compilés et y injecte automatiquement les modèles d'IA locaux (~5.1 Go) dans le dossier `release/SNM_Windows_Portable/`.*

### C. Compresser en ZIP
Dans le terminal :
```cmd
cd release
tar -a -c -f SNM_Windows_Portable_Complet.zip SNM_Windows_Portable
```

### D. Téléverser sur Hugging Face
Dans le terminal :
```cmd
cd ..
.venv\Scripts\python.exe build_tools\upload_windows_release.py
```
*Le script se charge d'uploader le nouveau ZIP vers Hugging Face et vous donnera le lien direct.*

### E. Mettre à jour la documentation (React)
Si l'URL change ou pour publier des modifications de la doc, placez-vous dans le dossier `snm-docs` :
```cmd
cd snm-docs
npm run build
npm run deploy
```

