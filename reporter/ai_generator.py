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
    ports = scan_data.get("ports", [])
    total_scanned = scan_data.get("total_scanned", len(ports))
    
    # Résumé des ports ouverts
    ports_summary = []
    for p in ports:
        port_num = p.get("port")
        service = p.get("service", "Inconnu")
        version = p.get("version", "N/A")
        vulnerable = p.get("label", "Inconnu")
        cves = [c.get("cve_id") for c in p.get("cves", [])]
        
        ports_summary.append({
            "port": port_num,
            "service": service,
            "version": version,
            "classification_ia": vulnerable,
            "cves_trouvees": cves
        })

    # Construction du prompt en français
    prompt = f"""
Vous êtes un expert en cybersécurité et en test d'intrusion.
Analysez les données de scan de vulnérabilités suivantes pour l'hôte cible {target} (effectué le {date}) et rédigez un rapport d'audit de sécurité professionnel, clair et exploitable.

Données du Scan :
- Cible : {target}
- Date du scan : {date}
- Nombre de ports scannés : {total_scanned}
- Détails des ports ouverts :
{json.dumps(ports_summary, indent=2, ensure_ascii=False)}

Votre rapport doit être rédigé entièrement en français et au format Markdown. Utilisez une structure claire avec les sections suivantes :
1. **Synthèse de la Sécurité Globale** : Un avis résumé sur le niveau de risque général de la machine (Faible, Moyen, Élevé, Critique) avec une explication synthétique.
2. **Analyse Détaillée par Port/Service** : Pour chaque port ouvert, expliquez ce qu'est le service, s'il présente un risque ou des CVEs, et la pertinence de la détection de l'IA.
3. **Plan de Remédiation** : Donnez des recommandations précises et ordonnées pour sécuriser cette machine cible (ex: fermer des ports, mettre à jour, masquer les bannières, etc.).

Soyez concis, professionnel et direct dans vos analyses. N'inventez pas de fausses vulnérabilités, tenez-vous en aux faits détectés par le scan.
"""

    # Appel de l'API Groq via urllib
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {
                "role": "system",
                "content": "Vous êtes un auditeur de cybersécurité professionnel. Rédigez des rapports de vulnérabilités synthétiques, structurés et clairs."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.2,
        "max_tokens": 1024
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
