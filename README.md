# 🛡️ Smart Network Mapper (Scanner Pro)

Un outil de cartographie réseau intelligent en Python, conçu pour automatiser la découverte d'hôtes actifs et l'analyse de ports sur un réseau local. Ce projet combine rapidité (via le multi-threading) et précision pour fournir une vue d'ensemble d'un sous-réseau.

---

## 🛠️ Architecture du Projet

Le projet est organisé de manière modulaire pour séparer la logique de réseau, l'interface utilisateur et la gestion des données.

### 📍 Fichiers et Dossiers Principaux

| Fichier / Dossier | Rôle & Fonctionnalité |
| :--- | :--- |
| **`main.py`** | **Point d'entrée du programme**. Gère l'interface interactive (CLI), les menus, les barres de progression et coordonne les différentes étapes du scan. |
| **`scanner/`** | **Cœur de la logique réseau**. Contient tous les modules de scan. |
| ∟ `host_discovery.py` | Responsable de la détection des machines allumées via des pings ICMP en parallèle. |
| ∟ `port_scanner.py` | Responsable de la vérification des ports TCP ouverts et de l'identification des services. |
| ∟ `device_info.py` | Extrait des détails supplémentaires : Nom d'hôte (Reverse DNS) et Adresse MAC (ARP). |
| ∟ `utils.py` | Utilitaires pour la validation et l'analyse des sous-réseaux (format CIDR). |
| **`outputs/`** | Répertoire de stockage des résultats. Contient le fichier `scan_result.json` généré après chaque scan. |
| **`tests/`** | Contient les tests unitaires (`pytest`) pour assurer la fiabilité des outils de scan. |
| **`requirements.txt`** | Liste toutes les bibliothèques externes nécessaires au fonctionnement. |

---

## 🚀 Fonctionnement Technique

### 1. Découverte d'Hôtes (Host Discovery)
Le programme prend un sous-réseau en entrée (ex: `192.168.1.0/24`). 
- **Mécanisme** : Il utilise la bibliothèque `icmplib` pour envoyer des paquets **ICMP Echo Request**.
- **Performance** : Utilise un `ThreadPoolExecutor` (Multi-threading) avec 100 agents (workers). Chaque worker "ping" une adresse IP différente en même temps, ce qui permet de scanner 254 adresses en quelques secondes seulement.

### 2. Informations de Périphérique (Device Info)
Pour chaque hôte détecté comme "Actif", le scanner tente deux actions :
- **Reverse DNS** : Utilise `socket.gethostbyaddr` pour trouver le nom de la machine sur le réseau.
- **ARP Scan** : Utilise la bibliothèque `scapy` pour envoyer une requête ARP et récupérer l'adresse MAC réelle de l'appareil (limité au réseau local).

### 3. Scanner de Ports (Port Scanner)
Une fois l'hôte ciblé, le programme propose 3 modes (Rapide, Complet ou Personnalisé).
- **Le "TCP Ping"** : Le scanner n'utilise pas ICMP ici, mais tente une connexion TCP via `socket.connect_ex`. Si la machine répond avec un signal de synchronisation, le port est marqué comme **OUVERT**.
- **Workers** : Le scan de ports utilise jusqu'à **200 threads parallèles** pour une vitesse optimale.
- **Identification des Services** : Pour chaque port ouvert, le script consulte la base de données locale du système d'exploitation (`C:\Windows\System32\drivers\etc\services` sur Windows) pour traduire le numéro de port (ex: 80) en nom de service (ex: HTTP).

### 4. Rapports et Sorties
- **Console** : Les résultats sont affichés dynamiquement avec `tqdm` (barre de progression) et `colorama` (couleurs pour les statuts).
- **JSON** : Une sauvegarde structurée est effectuée dans `outputs/scan_result.json`, facilitant l'intégration avec d'autres outils ou une analyse ultérieure.

## ⚙️ Détails Techniques Avancés

### 🧩 Système d'Importation Robuste (Fallback)
Dans le dossier `scanner/`, vous remarquerez une structure d'importation particulière :
```python
try:
    from .utils import parse_subnet
except ImportError:
    try:
        from scanner.utils import parse_subnet
    except ImportError:
        from utils import parse_subnet
```
**Pourquoi ce choix ?** Cela garantit que le script fonctionne dans trois scénarios différents :
1. **Exécution en tant que package** (`python -m scanner.host_discovery`).
2. **Importation depuis la racine** (`main.py` importe `scanner`).
3. **Exécution directe** depuis l'intérieur du dossier `scanner/`.

### 🧵 Architecture des Workers (Threading)
Le scanner utilise la classe `ThreadPoolExecutor` de Python pour paralléliser les tâches.
- **Scanning horizontal** : Pour la découverte d'hôtes, 254 IPs sont distribuées à 100 workers. Chaque worker attend une réponse ICMP de manière indépendante.
- **Scanning vertical** : Pour le scan de ports, jusqu'à 200 workers testent simultanément différents ports sur une seule machine.
- **Timeouts** : Des timeouts courts (0.5s à 1s) sont appliqués pour éviter qu'un hôte lent ou protégé par un pare-feu ne bloque l'ensemble de la file d'attente.

### 🔍 Résolution de Services
Le scanner ne se contente pas de dire qu'un port est ouvert. Il utilise la fonction `socket.getservbyport()` pour identifier le service probable (SSH, HTTP, HTTPS, etc.). Si le service est inconnu localement, il marque simplement "Service inconnu".

---


## 🚦 Installation et Lancement

### 1. Prérequis
- Python 3.8+
- Posséder les privilèges administrateur (requis pour les pings ICMP et les requêtes ARP Scapy).

### 2. Installation
```bash
# Cloner le projet
git clone <url-du-depot>
cd smart-network-mapper

# Installer les dépendances
pip install -r requirements.txt
```

### 3. Utilisation
```bash
python main.py
```

---

## 📝 À propos
Développé par **Amine NAHLI** dans le but de fournir un outil de diagnostic réseau simple, rapide et efficace.

> [!IMPORTANT]
> Cet outil est destiné à un usage légal et éthique uniquement. N'utilisez ce scanner que sur vos propres réseaux ou sur ceux pour lesquels vous avez une autorisation explicite.

## 🤝 Contribuer

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une issue ou à soumettre une pull request.

## 👨‍💻 Auteur

Développé par **Amine NAHLI**
