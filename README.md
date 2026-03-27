# 🛡️ Smart Network Mapper (Scanner Pro)

Bienvenue dans le **Smart Network Mapper**, un outil de cartographie réseau professionnel, intelligent et ultra-rapide conçu en Python. Que vous soyez un passionné de cybersécurité, un administrateur système ou un débutant curieux, cet outil vous permet d'explorer votre environnement réseau en toute simplicité.

---

## 🌍 1. Analyse Globale du Projet

### Le Problème 🚩
Dans un réseau, il est souvent difficile de savoir exactement **quelles machines sont allumées** et **quels services (ports) sont exposés**. Une faille de sécurité commence souvent par un port ouvert oublié ou une machine mal configurée.

### La Solution ✅
Le **Smart Network Mapper** automatise la découverte :
1. Il scanne votre réseau local pour trouver toutes les machines actives.
2. Il vous permet de cibler une machine spécifique (locale ou publique).
3. Il analyse les ports de cette machine pour identifier les services vulnérables ou actifs.

### Cas d'Utilisation Réels 💼
- **Cybersécurité** : Identifier des ports "sensibles" (comme une base de données MySQL) exposés par erreur.
- **Audit Réseau** : Vérifier que toutes les machines connectées à votre Wi-Fi sont bien les vôtres.
- **Dépannage** : Vérifier si un serveur Web ou un accès SSH est bien joignable.

---

## 🏗️ 2. Architecture du Projet

Le projet est structuré de manière modulaire : chaque fichier a un rôle précis pour garantir la clarté et la maintenance.

```text
smart-network-mapper/
├── main.py                 # 🚀 Point d'entrée (Interface Utilisateur)
├── scanner/                # 🧠 Cœur de la logique (Modules)
│   ├── host_discovery.py   # 🔎 Découverte des hôtes (TCP Ping)
│   ├── device_info.py      # ℹ️ Infos (MAC ARP, Hostname DNS)
│   ├── port_scanner.py     # ⚡ Scanner de ports multi-threadé
│   └── utils.py            # 🛠️ Utilitaires (Validation IP)
├── outputs/                # 📂 Résultats des scans (JSON)
└── tests/                  # 🧪 Tests de fiabilité
```

---

## 📖 3. Le Parcours du Scan : Une Histoire

Voici exactement ce qui se passe quand vous lancez le programme :

1.  **L'Accueil** : Une bannière stylée s'affiche.
2.  **La Phase de Découverte (LAN)** : Le programme vous demande un sous-réseau (ex: `192.168.1.0/24`). Il lance alors un "TCP Ping Sweep" ultra-rapide sur les 254 adresses possibles pour voir qui répond.
3.  **Le Tableau de Bord** : Un tableau s'affiche avec toutes les machines trouvées, leur nom (si disponible) et leur adresse MAC.
4.  **Le Choix Crucial** : Vous avez le choix :
    - Scanner une des machines que vous venez de trouver localement.
    - Scanner une **personnalité externe** (une IP publique sur Internet).
    - Quitter.
5.  **L'Analyse de Précision** : Si vous choisissez une IP publique, le scanner vérifie d'abord si elle est bien "publique" et si elle est joignable.
6.  **Le Verdict** : Vous choisissez votre mode de scan (Rapide, Complet ou Personnalisé). Une barre de progression s'anime, et à la fin, un rapport détaillé est généré sur votre écran et sauvegardé en fichier JSON.

---

## 🔬 4. Explication Fichiers & Fonctions (Niveau Expert)

### 🛠️ `scanner/utils.py`
Ce fichier est le "cerveau mathématique" de la validation.
- `validate_cidr(subnet)` : Vérifie que le format du réseau entré est correct.
- `is_public_ip(ip)` : Utilise une liste de plages réservées (10.0.0.0, 192.168.0.0, etc.) pour confirmer si une IP est exposée sur le Web ou purement locale.

### 🔎 `scanner/host_discovery.py`
C'est ici que la détection se passe.
- `tcp_ping(ip)` : Au lieu d'un simple "ping" classique (ICMP) souvent bloqué par les pare-feux, on tente une connexion TCP sur des ports communs (80, 443, 22). Si l'hôte répond, il est marqué comme actif.
- `scan_subnet(subnet)` : Utilise le **Multi-threading** pour scanner des centaines d'IP en simultané.

### ℹ️ `scanner/device_info.py`
Collecte les détails sur l'appareil.
- `get_hostname_dns(ip)` : Tente une "résolution inverse" pour trouver le nom de l'ordinateur (ex: `PC-DE-NICOLAS`).
- `get_mac_arp(ip)` : Utilise le protocole ARP (via la librairie Scapy) pour trouver l'adresse physique (MAC) de la carte réseau. *Uniquement pour le réseau local.*

### ⚡ `scanner/port_scanner.py`
Le moteur de scan à haute vitesse.
- `scan_tcp(ip, port)` : Tente une connexion "furtive" (`connect_ex`) pour voir si le port est ouvert.
- `scan_ports(ip, ports)` : Lance jusqu'à **200 agents (threads)** en même temps pour finir le scan en quelques secondes au lieu de plusieurs minutes.

---

## 📚 5. Les Bibliothèques Utilisées

- **`socket`** : La base de la communication réseau. Elle permet de "frapper à la porte" des ports TCP.
- **`ipaddress`** : Gère proprement les calculs complexes d'adresses IP.
- **`concurrent.futures`** : Permet le Multi-threading (faire plusieurs choses à la fois pour gagner du temps).
- **`scapy`** : Un outil puissant pour forger des paquets réseau (utilisé ici pour l'ARP).
- **`tqdm`** : Affiche la magnifique barre de progression pendant le scan.
- **`colorama`** : Ajoute de la couleur dans votre terminal pour une meilleure lisibilité.

---

## 🌐 6. Concepts Réseau pour Débutants

- **Adresse IP** : C'est "l'adresse postale" de votre ordinateur sur le réseau.
- **IP Publique vs Privée** : 
    - **Privée** : Votre adresse à l'intérieur de votre maison (ex: `192.168.x.x`).
    - **Publique** : Votre adresse sur Internet (celle que Google voit).
- **Le Port** : Imaginez un immeuble (l'IP). Chaque appartement est un "Port". Le port 80 est souvent pour le Web, le port 22 pour le contrôle à distance.
- **TCP (Transmission Control Protocol)** : C'est comme un appel téléphonique sécurisé. On appelle (`SYN`), on nous répond (`SYN-ACK`), et la connexion est établie.
- **ARP** : C'est la question "Qui a cette IP ? Donne-moi ton adresse physique MAC !".

---

## ⚙️ 7. Guide d'Installation

### 📋 Prérequis
Assurez-vous d'avoir [Python 3.10+](https://www.python.org/downloads/) installé.

### 🚀 Étapes
1.  **Cloner le projet** :
    ```bash
    git clone https://github.com/Amine-NAHLI/smart-network-mapper.git
    cd smart-network-mapper
    ```
2.  **Créer un environnement virtuel (optionnel mais conseillé)** :
    ```bash
    python -m venv .venv
    .venv\Scripts\activate  # Sur Windows
    ```
3.  **Installer les dépendances** :
    ```bash
    pip install -r requirements.txt
    ```

---

## 🎮 8. Comment l'Utiliser ?

Lancez simplement la commande suivante :
```bash
python main.py
```

1.  Entrez votre sous-réseau (ex: `192.168.1.0/24`).
2.  Attendez la fin de la découverte.
3.  Choisissez l'action souhaitée (1, 2 ou 3).
4.  Laissez le scanner faire son travail !

---

## 📊 9. Comprendre les Résultats

- **Latence** : Le temps (en millisecondes) que met un paquet pour faire l'aller-retour. Plus c'est bas, plus la connexion est rapide.
- **Statut OUVERT** : Un service est à l'écoute. C'est une porte ouverte.
- **Service** : Le nom du programme probable qui utilise ce port (ex: HTTP, SSH, FTP).

---

## 🔐 10. Conseils en Sécurité

> [!WARNING]
> Un port ouvert n'est pas une faille en soi, mais c'est une porte d'entrée potentielle.

**Que faire ?**
- Si vous trouvez un port `3306` (MySQL) ouvert sur une IP publique, **fermez-le immédiatement** via votre pare-feu !
- Ne scannez que les réseaux pour lesquels vous avez une **autorisation explicite**.

---

## 🚧 11. Limitations
- Le scanner ne détecte pas les machines qui ignorent totalement les requêtes TCP (machines ultra-sécurisées).
- L'adresse MAC n'est pas récupérable pour les IP publiques (Internet ne transmet pas cette info).

---

## 🚀 12. Améliorations Futures
- **Banner Grabbing** : Récupérer la version exacte du logiciel derrière le port.
- **Détection d'OS** : Deviner si la machine est sous Windows, Linux ou macOS.
- **Interface Graphique (GUI)** : Une fenêtre moderne pour remplacer le terminal.

---

## 👨‍💻 Auteur
Développé avec passion par **Amine NAHLI**.
🔗 [GitHub Profile](https://github.com/Amine-NAHLI)
