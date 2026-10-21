import json
import os
import ssl
import urllib.request
import urllib.error

def generate_ai_report(scan_data, api_key=None, output_path="outputs/ai_report.md"):
    """
    Génère un rapport textuel cyber expert en utilisant l'API Groq (Llama-3.3-70b).
    """
    if not api_key:
        api_key = os.environ.get("GROQ_API_KEY")
        
    if not api_key:
        error_msg = "Erreur : Clé API Groq non configurée (variable d'environnement GROQ_API_KEY manquante)."
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(error_msg)
        return output_path

    # Extraction des données clés
    target = scan_data.get("cible", "Inconnue")
    date = scan_data.get("date", "Inconnue")
    source = scan_data.get("source", "Inconnue")
    ports = scan_data.get("ports", [])
    total_scanned = scan_data.get("total_scanned", len(ports))
    
    # FIX CONTEXT OVERFLOW: Limiter à 30 ports max pour l'API Groq
    MAX_PORTS_IA = 30
    ports_to_process = ports[:MAX_PORTS_IA]
    
    # Résumé des ports ouverts
    ports_summary = []
    if len(ports) > MAX_PORTS_IA:
        ports_summary.append({
            "WARNING": f"Alerte : Le scan a détecté {len(ports)} ports ouverts. Pour éviter un dépassement de mémoire (Context Overflow), seuls les {MAX_PORTS_IA} premiers ports sont listés ci-dessous."
        })
        
    # Intégration du contexte MITRE ATT&CK et Threat Intelligence
    try:
        from .skills_knowledge import get_mitre_info, format_mitre_context_for_llm
    except ImportError:
        try:
            from reporter.skills_knowledge import get_mitre_info, format_mitre_context_for_llm
        except ImportError:
            from skills_knowledge import get_mitre_info, format_mitre_context_for_llm

    mitre_context = format_mitre_context_for_llm(ports_to_process)

    for p in ports_to_process:
        port_num = p.get("port")
        service = p.get("service", "Inconnu")
        version = p.get("version", "N/A")
        vulnerable = p.get("label", "Inconnu")
        cves = [c.get("cve_id") for c in p.get("cves", [])]
        has_cisa_kev = any(c.get("is_cisa_kev", False) for c in p.get("cves", []))
        mitre = get_mitre_info(port_num, service)
        
        ports_summary.append({
            "port": port_num,
            "service": service,
            "version": version,
            "classification_ia": vulnerable,
            "mitre_attack": f"{mitre['technique_id']} - {mitre['technique_name']} ({mitre['tactic']})",
            "cisa_kev_active_exploit": "OUI (ALERTE CRITIQUE)" if has_cisa_kev else "Non",
            "cves_trouvees": cves
        })

    # Construction du prompt en français enrichi MITRE & CISA KEV optimisé pour Telegram
    prompt = f"""
Vous êtes un auditeur senior en cybersécurité et analyste SOC de référence (expert NIST SP 800-115 et MITRE ATT&CK).
Votre mission est de rédiger un rapport d'audit de sécurité d'un niveau d'excellence absolu, ULTRA-VISUEL, PARFAITEMENT STRUCTURÉ et AGRÉABLE À LIRE sur Telegram et sur tableau de bord d'incident.

Données Réelles du Scan :
- Cible : {target}
- Date du scan : {date}
- Source d'exécution : {source}
- Nombre total de ports scannés : {total_scanned}
- Nombre de ports ouverts : {len(ports_to_process)}
- Détails techniques des services découverts :
{json.dumps(ports_summary, indent=2, ensure_ascii=False)}

Contexte de Cartographie des Menaces (MITRE ATT&CK & Durcissement) :
{mitre_context}

CONSIGNES DE MISE EN PAGE ET DE STYLE (OBLIGATOIRES POUR TELEGRAM) :
1. Démarrez IMMÉDIATEMENT par le cadre d'en-tête ci-dessous, SANS aucun mot d'introduction ni formule de politesse ("Voici le rapport...").
2. Utilisez une typographie dynamique avec des séparateurs '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' et des emojis professionnels.
3. Ne générez AUCUN grand tableau en barres '| col |' (inadapté sur smartphone). Utilisez des fiches à puces claires et aérées.
4. Encadrez les commandes techniques, services et adresses IP avec des backticks `...` pour une lisibilité maximale.

Structure stricte à respecter mot à mot pour les sections :

╔══════════════════════════════════════════════════╗
║   🛰️ SMART NETWORK MAPPER — AUDIT DE SÉCURITÉ   ║
╚══════════════════════════════════════════════════╝

🎯 **CIBLE :** `{target}`  |  📅 **HORODATAGE :** `{date}`
📊 **SURFACE D'ATTAQUE :** {len(ports_to_process)} port(s) ouvert(s) sur {total_scanned} audités

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 **SYNTHÈSE EXÉCUTIVE & NIVEAU DE RISQUE GLOBAL : [CRITIQUE / ÉLEVÉ / MOYEN / FAIBLE]**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
(Rédigez 2 à 3 phrases percutantes évaluant l'exposition globale, le risque d'accès initial ou de mouvement latéral, et signalez en priorité les failles CISA KEV ou expositions de base de données).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 **CARTOGRAPHIE DES SERVICES & ANALYSE DE MENACES**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pour chaque port ouvert, présentez une fiche claire sous cette forme :

📌 **PORT {{port}}/{{protocole}} — {{SERVICE}}** `({{version}})`
   • **Statut IA :** 🔴 `VULNÉRABLE` ou 🟢 `SÉCURISÉ` (Confiance : XX%)
   • **Technique MITRE ATT&CK :** `TXXXX - Nom de la technique`
   • **Exploit Actif (CISA KEV) :** ⚠️ `OUI (Exploit public actif)` ou `Non`
   • **CVEs Détectées :** `CVE-XXXX-XXXX` (ou Aucune)
   • **Diagnostic :** (1 à 2 phrases précises sur le vecteur d'attaque et l'impact)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛠️ **PLAN DE DURCISSEMENT PRIORISÉ (NIST SP 800-115)**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Ordonnez les actions concrètes par niveau de criticité (1️⃣ Priorité Immédiate, 2️⃣ Priorité Haute, 3️⃣ Mesure Recommandée) :
Chaque mesure doit comporter l'action et un bloc de code prêt à copier (ex: configuration pare-feu, mise à niveau de paquet, directive de service).

Soyez rigoureux, concis et d'une précision technique chirurgicale.
"""

    # Appel de l'API Groq via urllib
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    payload = {
        "model": os.environ.get("GROQ_MODEL", "qwen/qwen3.8-27b"),
        "messages": [
            {
                "role": "system",
                "content": "Vous êtes un auditeur de cybersécurité professionnel. Vous produisez des rapports d'audit hautement visuels, synthétiques et percutants, optimisés pour Telegram et les décideurs techniques."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.2,
        "max_tokens": 2048
    }

    try:
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")
        ctx = ssl.create_default_context()

        with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
            res_body = response.read().decode("utf-8")
            res_json = json.loads(res_body)
            ai_text = res_json["choices"][0]["message"]["content"]
            
            # Écriture du rapport
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(ai_text)
            
            return output_path
            
    except Exception as e:
        error_msg = f"Erreur lors de l'appel à l'API Groq : {str(e)}"
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(error_msg)
        return output_path
