"""
flask_server.py
---------------
Serveur API Flask pour la prediction de vulnerabilites.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from model.predictor import predict
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Autoriser les requetes cross-origin

# ------------------------------------------------------------------------------
# Gestion des erreurs JSON
# ------------------------------------------------------------------------------
@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad Request", "message": str(e.description)}), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not Found", "message": "La ressource demandee est introuvable"}), 404

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal Server Error: {e}")
    return jsonify({"error": "Internal Server Error", "message": "Une erreur inattendue est survenue"}), 500


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------

@app.route('/health', methods=['GET'])
def health():
    """Route de check-up simple."""
    return jsonify({"status": "ok"})


@app.route('/predict', methods=['POST'])
def predict_single():
    """
    Predite la vulnerabilite pour un service unique.
    JSON attendu : { "port": 80, "version": "...", "service": "..." }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON manquant ou malforme"}), 400

    port = data.get("port", 0)
    version = data.get("version", "")
    service = data.get("service", "INCONNU")

    try:
        prediction = predict(
            port, 
            version, 
            service=service, 
            protocol=data.get("protocol", "tcp"), 
            os_hint=data.get("os_hint", "")
        )
        
        # Formatage de la reponse demandee par l'utilisateur
        # On multiplie confidence par 100 si on veut un affichage en pourcentage (87.3)
        res = {
            "port": port,
            "service": service,
            "vulnerable": prediction["vulnerable"],
            "confidence": round(prediction["confidence"] * 100, 2),
            "label": prediction["label"]
        }
        return jsonify(res)
    except Exception as e:
        logger.exception("Erreur lors de la prediction")
        return jsonify({"error": "Erreur de prediction", "detail": str(e)}), 500


@app.route('/predict/batch', methods=['POST'])
def predict_batch():
    """
    Prend une liste de ports (format scan_result.json) et l'enrichit.
    Accepte soit une liste directe : [ { "port": 80, ... }, ... ]
    Soit un dictionnaire : { "ports": [ { "port": 80, ... }, ... ] }
    """
    raw_data = request.get_json(silent=True)
    
    if isinstance(raw_data, dict) and "ports" in raw_data:
        ports_list = raw_data["ports"]
    elif isinstance(raw_data, list):
        ports_list = raw_data
    else:
        return jsonify({"error": "La requete doit etre une liste ou un dictionnaire avec une cle 'ports'"}), 400

    enriched_list = []
    
    try:
        for item in ports_list:
            port = item.get("port", 0)
            version = item.get("version", "")
            
            # Prediction enrichie avec service, protocole et os_hint s'ils sont présents
            pred = predict(
                port, 
                version, 
                service=item.get("service", ""),
                protocol=item.get("protocole", "tcp"), # 'protocole' est utilisé dans l'export JSON
                os_hint=item.get("os_hint", "")
            )
            
            # Enrichissement de l'objet d'origine
            enriched_item = item.copy()
            enriched_item.update({
                "vulnerable": pred["vulnerable"],
                "confidence": round(pred["confidence"] * 100, 2),
                "label": pred["label"]
            })
            enriched_list.append(enriched_item)
            
        return jsonify(enriched_list)
    except Exception as e:
        logger.exception("Erreur lors du traitement par lot")
        return jsonify({"error": "Erreur de traitement batch", "detail": str(e)}), 500


if __name__ == "__main__":
    # Tourne sur le port 5000, debug desactive
    logger.info("Demarrage du serveur de prediction sur le port 5000...")
    app.run(host="0.0.0.0", port=5000, debug=False)
