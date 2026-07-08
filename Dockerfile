# Utiliser une image Python officielle légère
FROM python:3.11-slim

# Mettre à jour le système et installer Nmap/Scapy (requis pour les scans réseau avancés)
RUN apt-get update && apt-get install -y \
    iputils-ping \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Définir le répertoire de travail dans le conteneur
WORKDIR /app

# Copier les fichiers de dépendances
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copier tout le code source dans le conteneur
COPY . .

# Créer les dossiers de sortie et de cache par défaut
RUN mkdir -p outputs model

# Définir la commande par défaut (Lance le scan CLI interactif)
CMD ["python", "cli/main.py"]
