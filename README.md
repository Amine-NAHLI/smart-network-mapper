# 🛰️ Smart Network Mapper

Bienvenue dans le projet **Smart Network Mapper** ! Cet outil est un scanner réseau complet conçu pour être à la fois **puissant** pour les initiés et **pédagogique** pour les débutants.

Il permet d'explorer votre réseau local (LAN) ou des serveurs distants pour découvrir quels appareils sont actifs et quels services ils hébergent.

---

## 📌 Présentation du projet

- **Nom du projet** : Smart Network Mapper
- **Objectif principal** : Cartographier un réseau informatique en identifiant les machines connectées et leurs "portes d'entrée" (les ports).
- **Problème résolu** : Savoir exactement ce qui tourne sur son réseau, détecter des appareils inconnus ou vérifier la sécurité de ses propres services.
- **À qui il est destiné** : Étudiants en informatique, curieux de la cybersécurité, ou administrateurs réseau cherchant un outil simple et transparent.

---

## ⚙️ Fonctionnalités

✅ **Détection automatique du réseau** : Identifie votre carte Wi-Fi ou Ethernet et calcule votre plage d'adresses IP.  
✅ **Scan d'hôtes (Host Discovery)** : Trouve toutes les machines allumées sur votre réseau local.  
✅ **Scan de ports multi-threadé** : Analyse des milliers de ports en quelques secondes grâce à l'exécution en parallèle.  
✅ **Identification de services** : Reconnaît automatiquement les services courants (HTTP, SSH, FTP, etc.).  
✅ **Banner Grabbing & Versioning** : Tente de lire la "signature" du service pour deviner sa version exacte.  
✅ **Support IP Publique** : Permet aussi de scanner des serveurs sur Internet (avec validation de sécurité).  
✅ **Export JSON** : Sauvegarde automatiquement les résultats pour une analyse ultérieure.

---

## 🧠 Comment ça marche ?

Le programme suit un flux logique rigoureux pour garantir rapidité et précision.

### Flux du programme étape par étape :

1.  **Initialisation** : Le programme détecte votre configuration réseau actuelle (IP locale, masque).
2.  **Découverte** : Il envoie des requêtes légères (TCP Ping) à toutes les IP possibles du réseau pour voir qui répond.
3.  **Collecte d'infos** : Pour chaque machine trouvée, il récupère son nom d'hôte (DNS) et son adresse MAC (ARP).
4.  **Ciblage** : L'utilisateur choisit une machine spécifique à analyser plus en profondeur.
5.  **Scan de ports** : Le programme tente d'ouvrir une connexion sur chaque port demandé.
6.  **Inspection** : Si un port est ouvert, il télécharge la "bannière" (le message d'accueil du service) pour identifier le logiciel utilisé.
7.  **Rapport** : Il affiche un tableau récapitulatif coloré et génère un fichier JSON.

---

## 🗂️ Structure du projet

L'organisation des fichiers respecte les bonnes pratiques de modularité en Python :

- 📄 `main.py` : Le **cerveau** du projet. Il gère l'interface utilisateur, les menus et coordonne les différents modules de scan.
- 📁 `scanner/` : Le dossier contenant toute la **logique technique**.
  - `host_discovery.py` : Contient les fonctions pour trouver les machines sur le réseau (Ping).
  - `port_scanner.py` : Gère le scan des ports TCP, la lecture des bannières et la détection de version.
  - `device_info.py` : Utilise des protocoles comme ARP pour obtenir les adresses MAC et le DNS inversé pour les noms.
  - `utils.py` : Fonctions utilitaires pour valider les adresses IP et manipuler les réseaux CIDR.
- 📁 `outputs/` : Dossier où sont stockés les rapports de scan (ex: `scan_result.json`).
- 📄 `requirements.txt` : Liste des bibliothèques externes nécessaires.

---

## 🔍 Explication du code

### 1. Les bibliothèques clés utilisées

- **`scapy`** : Une bibliothèque ultra-puissante pour manipuler les paquets réseau (utilisée ici pour les requêtes ARP).
- **`socket`** : Le module standard de Python pour les communications réseau de bas niveau.
- **`concurrent.futures`** : Permet de lancer plusieurs scans en même temps (Multi-threading) pour aller 100x plus vite.
- **`colorama`** : Ajoute des couleurs dans le terminal pour rendre le texte lisible.
- **`tqdm`** : Affiche de jolies barres de progression pendant les scans longs.

### 2. Zoom sur une fonction : `scan_tcp`

Cette fonction est le cœur du scanner de ports. Voici son principe :

```python
# Extrait simplifié de scanner/port_scanner.py
def scan_tcp(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.5)
        result = s.connect_ex((ip, port))
        if result == 0:
            return "OUVERT"
        return "FERMÉ"
```

- `socket.AF_INET` : On communique via IPv4.
- `socket.SOCK_STREAM` : On utilise le protocole TCP (fiable).
- `connect_ex` : Tente la connexion. S'il renvoie `0`, la porte est ouverte !

---

## 💻 Installation et exécution

### Prérequis

- **Python 3.8+** installé sur votre système.
- Droits administrateur (requis pour certaines fonctions réseau comme ARP/Scapy).

### Installation

1. Clonez ou téléchargez le projet.
2. Ouvrez un terminal dans le dossier du projet.
3. Installez les dépendances :
   ```bash
   pip install -r requirements.txt
   ```

### Lancement

Pour démarrer le programme, lancez simplement :

```bash
python main.py
```

---

## 📡 Exemple concret d'utilisation

Imaginez que vous voulez voir ce qui tourne sur votre box internet ou votre ordinateur :

1. **Entrée** : Vous choisissez le mode "Détection automatique".
2. **Traitement** :
   - Le programme trouve votre réseau : `192.168.1.0/24`.
   - Il détecte votre PC à l'IP `192.168.1.15`.
   - Vous lancez un scan rapide sur les ports communs.
3. **Sortie** :
   - Le port `80` est **OUVERT**.
   - Service détecté : `HTTP`.
   - Version : `Apache/2.4.41`.
   - Un fichier `scan_result.json` est créé avec ces détails.

---

## ⚠️ Gestion des erreurs

Le programme est robuste et prévoit plusieurs cas de figure :

- **Timeout** : Si une machine est trop lente à répondre, le programme passe à la suivante sans se bloquer.
- **Permission refusée** : Si Scapy ne peut pas accéder à la carte réseau (souvent par manque de privilèges `sudo` ou Admin), le programme bascule sur des méthodes alternatives plus simples.
- **IP Invalide** : Le module `utils.py` vérifie chaque saisie utilisateur pour éviter les plantages.

---

## 🚀 Améliorations possibles

- [ ] **Scan UDP** : Ajouter le support pour le protocole UDP (plus complexe car sans connexion).
- [ ] **Détection d'OS** : Utiliser Scapy pour analyser la pile TCP/IP et deviner si la cible est sous Windows, Linux ou Android.
- [ ] **Interface Graphique (GUI)** : Créer une fenêtre avec des graphiques pour visualiser le réseau.
- [ ] **Historique** : Garder une trace de tous les scans passés dans une base de données SQLite.

---

## 📖 Glossaire

- **IP (Internet Protocol)** : L'adresse postale de votre machine sur le réseau.
- **Port** : Un numéro (0 à 65535) qui définit une application spécifique (ex: 80 pour le web).
- **CIDR (192.168.1.0/24)** : Une notation raccourcie pour définir une plage d'adresses IP.
- **ARP** : Le protocole qui permet de traduire une IP en adresse physique (MAC) sur un réseau local.

---

💡 **Conseil d'expert** : Pour comprendre le projet, commencez par lire `scanner/utils.py` (la base), puis remontez vers `main.py`.

_Développé avec ❤️ par Amine Nahli._
