"""
reporter/skills_knowledge.py
-----------------------------
Base de connaissances de cybersécurité inspirée d'Anthropic Cybersecurity Skills
et du framework MITRE ATT&CK v14.

Fournit la matrice de correspondance entre les ports/services réseau détectés
et les Tactiques, Techniques et Procédures (TTP) officielles MITRE ATT&CK,
ainsi que les playbooks de durcissement (Hardening & Remediation Playbooks).
"""

from typing import Dict, List, Any


# ──────────────────────────────────────────────────────────────
# Matrice MITRE ATT&CK (Enterprise Matrix)
# ──────────────────────────────────────────────────────────────
MITRE_ATTACK_MAPPING: Dict[int, Dict[str, Any]] = {
    21: {
        "technique_id": "T1021.002",
        "technique_name": "Remote Services: FTP / Cleartext Protocol",
        "tactic": "Lateral Movement / Exfiltration",
        "mitre_url": "https://attack.mitre.org/techniques/T1021/",
        "risk_summary": "Protocole en clair transmettant identifiants et données sans chiffrement.",
        "remediation_playbook": "Désactiver FTP au profit de SFTP/SCP (port 22) ou FTPS (TLS). Imposer l'authentification par clé et bannir les accès anonymes.",
    },
    22: {
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "tactic": "Lateral Movement / Initial Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1021/004/",
        "risk_summary": "Point d'entrée pour des attaques par force brute ou exploitation de failles serveur (ex: regreSSHion).",
        "remediation_playbook": "Désactiver l'authentification par mot de passe (clés Ed25519 uniquement), désactiver PermitRootLogin, changer le port par défaut et installer fail2ban.",
    },
    23: {
        "technique_id": "T1040",
        "technique_name": "Network Sniffing / Unencrypted Legacy Protocol",
        "tactic": "Credential Access / Discovery",
        "mitre_url": "https://attack.mitre.org/techniques/T1040/",
        "risk_summary": "Protocole obsolète vulnérable à l'interception totale des identifiants en clair.",
        "remediation_playbook": "Désactiver immédiatement Telnet et migrer vers SSHv2 avec chiffrement fort.",
    },
    25: {
        "technique_id": "T1071.003",
        "technique_name": "Application Layer Protocol: Mail Protocols",
        "tactic": "Command and Control / Initial Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1071/003/",
        "risk_summary": "Vecteur potentiel pour relais de spam (Open Relay), usurpation d'identité et phishing.",
        "remediation_playbook": "Configurer SPF, DKIM, DMARC, désactiver le relais ouvert (open relay) et forcer STARTTLS.",
    },
    53: {
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control / Exfiltration",
        "mitre_url": "https://attack.mitre.org/techniques/T1071/004/",
        "risk_summary": "Canal d'exfiltration de données par tunnel DNS ou amplification DDoS.",
        "remediation_playbook": "Désactiver la récursion ouverte pour les clients externes, activer DNSSEC et surveiller les requêtes anormales.",
    },
    80: {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application: HTTP",
        "tactic": "Initial Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
        "risk_summary": "Exposition Web non chiffrée vulnérable aux injections (SQLi, XSS, RCE, Path Traversal).",
        "remediation_playbook": "Rediriger 100% du trafic HTTP vers HTTPS (port 443), déployer un WAF (ModSecurity / Cloudflare) et appliquer les correctifs applicatifs OWASP Top 10.",
    },
    135: {
        "technique_id": "T1021.003",
        "technique_name": "Remote Services: Distributed Component Object Model (DCOM/RPC)",
        "tactic": "Lateral Movement",
        "mitre_url": "https://attack.mitre.org/techniques/T1021/003/",
        "risk_summary": "Service Microsoft RPC très exposé aux attaques de mouvement latéral (PetitPotam, ZeroLogon).",
        "remediation_playbook": "Bloquer le port 135 au niveau du pare-feu périmétrique et segmenter le réseau interne.",
    },
    139: {
        "technique_id": "T1021.002",
        "technique_name": "Remote Services: SMB / NetBIOS",
        "tactic": "Lateral Movement",
        "mitre_url": "https://attack.mitre.org/techniques/T1021/002/",
        "risk_summary": "NetBIOS obsolète vulnérable à l'énumération de partages et d'utilisateurs.",
        "remediation_playbook": "Désactiver NetBIOS sur TCP/IP et n'autoriser que SMBv3 chiffré.",
    },
    443: {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application: HTTPS",
        "tactic": "Initial Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
        "risk_summary": "Surface d'attaque web sécurisée en transit mais vulnérable aux failles applicatives et de configuration TLS.",
        "remediation_playbook": "Désactiver SSLv3, TLS 1.0 et TLS 1.1. Forcer TLS 1.2/1.3 avec suites de chiffrement AEAD (AES-GCM / ChaCha20) et activer HSTS.",
    },
    445: {
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services: SMB",
        "tactic": "Lateral Movement / Initial Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1210/",
        "risk_summary": "Cible privilégiée des ransomwares (EternalBlue, WannaCry, NotPetya).",
        "remediation_playbook": "Désactiver impérativement SMBv1, forcer la signature SMB (SMB Signing) et bloquer l'accès depuis Internet.",
    },
    3306: {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts: Database Exposure (MySQL)",
        "tactic": "Initial Access / Defense Evasion",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/",
        "risk_summary": "Base de données exposée sur le réseau pouvant subir des attaques par force brute ou extraction de données.",
        "remediation_playbook": "Restreindre l'écoute à 127.0.0.1 (bind-address), utiliser un tunnel SSH/VPN pour l'administration et imposer des mots de passe robustes avec le principe du moindre privilège.",
    },
    3389: {
        "technique_id": "T1021.001",
        "technique_name": "Remote Services: Remote Desktop Protocol (RDP)",
        "tactic": "Lateral Movement / Initial Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1021/001/",
        "risk_summary": "Cible majeure d'attaques par force brute, BlueKeep (CVE-2019-0708) et accès distant non autorisé.",
        "remediation_playbook": "Ne jamais exposer RDP directement sur Internet. Utiliser une passerelle VPN avec MFA (authentification multi-facteurs) et activer NLA (Network Level Authentication).",
    },
    5432: {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts: PostgreSQL Exposure",
        "tactic": "Initial Access / Persistence",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/",
        "risk_summary": "Exposition de SGBD permettant l'exécution de commandes système via fonctions administratives mal configurées.",
        "remediation_playbook": "Configurer pg_hba.conf avec des règles d'accès strictes (scram-sha-256) et isoler dans un sous-réseau privé.",
    },
    6379: {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application: Redis In-Memory Store",
        "tactic": "Initial Access / Execution",
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
        "risk_summary": "Instance Redis sans mot de passe permettant l'écriture de clés SSH ou de tâches cron arbitraires (RCE).",
        "remediation_playbook": "Activer requirepass, désactiver les commandes dangereuses (CONFIG, FLUSHALL) via rename-command et restreindre l'écoute à localhost.",
    },
    8080: {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application: HTTP Proxy / Alt Web",
        "tactic": "Initial Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
        "risk_summary": "Panneaux d'administration ou microservices fréquemment mal protégés (Apache Tomcat, Jenkins, Spring Boot).",
        "remediation_playbook": "Protéger par authentification forte, restreindre les adresses IP autorisées et maintenir à jour les frameworks applicatifs.",
    },
}


def get_mitre_info(port: int, service: str = "") -> Dict[str, Any]:
    """
    Retourne les métadonnées MITRE ATT&CK et le playbook de remédiation pour un port donné.
    """
    if port in MITRE_ATTACK_MAPPING:
        return MITRE_ATTACK_MAPPING[port]

    # Fallback générique pour ports web alternatifs
    if "http" in service.lower() or port in [8000, 8008, 8888, 9090, 8443]:
        return {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "mitre_url": "https://attack.mitre.org/techniques/T1190/",
            "risk_summary": "Service applicatif exposé pouvant présenter des failles de sécurité logicielles.",
            "remediation_playbook": "Isoler derrière un reverse-proxy avec filtrage WAF, chiffrement TLS et contrôle d'accès strict.",
        }

    return {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "mitre_url": "https://attack.mitre.org/techniques/T1046/",
        "risk_summary": "Port ouvert détecté participant à la surface d'attaque globale.",
        "remediation_playbook": "Fermer le port si le service n'est pas indispensable ou restreindre l'accès via pare-feu.",
    }


def format_mitre_context_for_llm(open_ports: List[Dict[str, Any]]) -> str:
    """
    Génère un bloc de contexte structuré MITRE ATT&CK à injecter dans le prompt de Groq Llama-3.3.
    """
    if not open_ports:
        return "Aucun port ouvert détecté."

    lines = ["### 🎯 Cartographie MITRE ATT&CK & Playbooks de Durcissement :"]
    for p in open_ports[:15]:  # Top 15 pour éviter la surcharge de contexte
        port = p.get("port", 0)
        svc = p.get("service", "unknown")
        ver = p.get("version", "N/A")
        info = get_mitre_info(port, svc)

        lines.append(
            f"- **Port {port} ({svc} - {ver})** : "
            f"Technique `{info['technique_id']}` ({info['technique_name']}) | "
            f"Tactique : *{info['tactic']}* | "
            f"Remédiation : {info['remediation_playbook']}"
        )

    return "\n".join(lines)
