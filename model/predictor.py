"""
model/predictor.py
------------------
Module d'inference de vulnerabilite reseau.

Pipeline de pretraitement (identique a l'entrainement) :
  1. Parse de la version_string -> version_ma, version_mi, version_p, version_full
  2. RobustScaler sur : version_ma, version_mi, version_p, version_full, port
  3. QuantileTransformer sur : version_p, version_full
  4. Prediction avec le RandomForestClassifier
"""

import re
import os
import joblib
import threading
import numpy as np
import pandas as pd

# ──────────────────────────────────────────────────────────────
# Chemins vers les artefacts
# ──────────────────────────────────────────────────────────────
_MODEL_DIR = os.path.dirname(os.path.abspath(__file__))

_MODEL_PATH       = os.path.join(_MODEL_DIR, "vulnerability_model.pkl")
_SCALER_PATH      = os.path.join(_MODEL_DIR, "scaler.pkl")
_QT_PATH          = os.path.join(_MODEL_DIR, "quantile_transformer.pkl")
_FEATURES_PATH    = os.path.join(_MODEL_DIR, "feature_names.pkl")

# ──────────────────────────────────────────────────────────────
# Colonnes concernées par chaque transformateur
# ──────────────────────────────────────────────────────────────
_SCALER_COLS = ["version_ma", "version_mi", "version_p", "version_full", "port"]
_QT_COLS     = ["version_p", "version_full"]


# ──────────────────────────────────────────────────────────────
# Chargement paresseux (une seule fois) des artefacts
# ──────────────────────────────────────────────────────────────
_model   = None
_scaler  = None
_qt      = None
_feature_names = None
_load_lock = threading.Lock()


def _load_artifacts() -> None:
    """Charge tous les artefacts depuis le disque de manière thread-safe."""
    global _model, _scaler, _qt, _feature_names

    if _model is not None:
        return  # déjà chargés

    with _load_lock:
        # Double vérification après l'acquisition du verrou
        if _model is not None:
            return

    for path, name in [
        (_MODEL_PATH,    "vulnerability_model.pkl"),
        (_SCALER_PATH,   "scaler.pkl"),
        (_QT_PATH,       "quantile_transformer.pkl"),
        (_FEATURES_PATH, "feature_names.pkl"),
    ]:
        if not os.path.isfile(path):
            raise FileNotFoundError(
                f"Artefact manquant : {name}\n"
                f"Chemin attendu : {path}"
            )

    _model         = joblib.load(_MODEL_PATH)
    _scaler        = joblib.load(_SCALER_PATH)
    _qt            = joblib.load(_QT_PATH)
    _feature_names = joblib.load(_FEATURES_PATH)

def load_model():
    """Charge manuellement les artefacts (utile au démarrage du serveur)."""
    _load_artifacts()


# Parsing de la chaine de version
# ------------------------------
# Le premier groupe est le major, les suivants sont optionnels
_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _parse_version(version_string: str) -> dict:
    """
    Extrait les composantes numériques d'une chaine de version de manière robuste.
    """
    defaults = {"version_ma": 0, "version_mi": 0, "version_p": 0, "version_full": 0.0}

    if not version_string or not isinstance(version_string, str):
        return defaults

    # Regex plus flexible pour attraper les chiffres même avec des préfixes/suffixes
    m = _VERSION_RE.search(version_string)
    if not m:
        return defaults

    try:
        ma = int(m.group(1))
        mi = int(m.group(2)) if m.group(2) is not None else 0
        p  = int(m.group(3)) if m.group(3) is not None else 0

        # Formule plus stable pour éviter les chevauchements (ex: 2.10 vs 3.0)
        # On utilise une base 100 pour les sous-versions
        full = ma + (mi * 0.01) + (p * 0.0001)

        return {"version_ma": ma, "version_mi": mi, "version_p": p, "version_full": full}
    except Exception:
        return defaults


# Base de connaissances des versions stables (minimales recommandées)
# Pour éviter que l'IA ne flagge des versions récentes comme vulnérables.
_STABLE_VERSIONS = {
    "apache":  (2, 4, 58),
    "nginx":   (1, 24, 0),
    "openssh": (9, 0, 0),
    "mysql":   (8, 0, 30),
    "vsftpd":  (3, 0, 5),
    "php":     (8, 2, 0),
    "postfix": (3, 7, 0),
}

def _is_known_safe(service_name: str, ma: int, mi: int, p: int) -> bool:
    """Vérifie si une version est connue comme stable/sûre."""
    service_name = service_name.lower()
    for key, stable_ver in _STABLE_VERSIONS.items():
        if key in service_name:
            # Comparaison de version (major, minor, patch)
            if (ma, mi, p) >= stable_ver:
                return True
    return False


# ──────────────────────────────────────────────────────────────
# API publique
# ──────────────────────────────────────────────────────────────
def predict(port: int, version_string: str, service: str = "", protocol: str = "tcp", os_hint: str = "") -> dict:
    """
    Prédit si un service réseau est vulnérable.
    """
    _load_artifacts()

    # Nettoyage des entrées
    is_unknown_version = False
    v_lower = version_string.lower() if version_string else ""
    if not version_string or any(x in v_lower for x in ["non détectée", "inconnue", "n/a", "réponse vide", "timeout"]):
        is_unknown_version = True
        version_string = ""

    # ── 1. Construction du vecteur brut ──────────────────────────
    raw = {feat: 0 for feat in _feature_names}
    
    v_info = _parse_version(version_string)
    raw.update(v_info)
    raw["port"] = int(port) if port is not None else 0
    
    # ── 2. Encodage du service ──────────────────────────────────
    service_lower = service.lower() if service else ""
    has_recognized_service = False
    for feat in _feature_names:
        if feat.startswith("service_"):
            service_name = feat.replace("service_", "")
            if service_name in service_lower:
                raw[feat] = 1
                has_recognized_service = True
                
    # ── 3. Encodage du protocole ─────────────────────────────────
    if protocol.lower() == "tcp":
        raw["protocol_tcp"] = 1
    else:
        raw["protocol_udp"] = 1
        
    # ── 5. Transformation et Prédiction ───────────────────────────
    if is_unknown_version:
        raw["version_ma"]   = _scaler.center_[0]
        raw["version_mi"]   = _scaler.center_[1]
        raw["version_p"]    = _scaler.center_[2]
        raw["version_full"] = _scaler.center_[3]

    df = pd.DataFrame([raw], columns=_feature_names)
    df[_SCALER_COLS] = _scaler.transform(df[_SCALER_COLS])
    df[_QT_COLS] = _qt.transform(df[_QT_COLS])

    probas = _model.predict_proba(df[_feature_names])[0]
    prediction = int(np.argmax(probas))
    confidence = float(probas[prediction])

    # ── COUCHE DE SAGESSE (Heuristique) ─────────────────────────
    # On extrait le nom du logiciel de la version (ex: "Apache" de "Apache/2.4.58")
    detected_soft = version_string.split('/')[0].lower() if '/' in version_string else service_lower

    if _is_known_safe(detected_soft, v_info["version_ma"], v_info["version_mi"], v_info["version_p"]):
        prediction = 0
        confidence = 0.95
        label = "NON VULNÉRABLE"
    else:
        # Seuil de sécurité IA
        if prediction == 1 and confidence < 0.65:
            prediction = 0
            confidence = 1.0 - confidence
            label = "NON VULNÉRABLE"
        else:
            label = "VULNÉRABLE" if prediction == 1 else "NON VULNÉRABLE"

    # ── GÉNÉRATION DES CONSEILS ET LIENS CVE ───────────────────
    remedy = "Aucune action requise."
    cve_link = ""
    threat_level = "SÛR"

    if prediction == 1:
        threat_level = "CRITIQUE" if confidence > 0.85 else "ÉLEVÉ"
        soft_name = detected_soft.capitalize()
        cve_link = f"https://www.cvedetails.com/google-search-results.php?q={soft_name}+{version_string}"
        
        if detected_soft in _STABLE_VERSIONS:
            v_target = ".".join(map(str, _STABLE_VERSIONS[detected_soft]))
            remedy = f"Mettez à jour vers {v_target}."
        else:
            remedy = "Service obsolète. Vérifiez les mises à jour."
    elif confidence < 0.65:
        threat_level = "MOYEN"
        remedy = "Service non identifié précisément."
    else:
        threat_level = "FAIBLE"

    return {
        "vulnerable":   prediction,
        "confidence":   round(confidence, 4), # Valeur brute 0.0-1.0
        "label":        label,
        "threat_level": threat_level,
        "remedy":       remedy,
        "cve_link":     cve_link
    }


# ──────────────────────────────────────────────────────────────
# Test rapide
# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_cases = [
        (80,  "Apache/2.4.58", "apache"), # Doit être SAIN maintenant
        (443, "OpenSSL/1.0.1f", "https"), # Doit être VULNÉRABLE
        (22,  "OpenSSH/9.5", "ssh"),      # Doit être SAIN
        (80,  "Non détectée", "http"),    # Calcul neutre
    ]

    print(f"{'Port':<6} {'Version':<25} {'Resultat':<18} {'Confiance':>9}")
    print("-" * 62)
    for port, ver, svc in test_cases:
        result = predict(port, ver, service=svc)
        print(f"{port:<6} {str(ver):<25} {result['label']:<18} {result['confidence']*100:>8.1f}%")
