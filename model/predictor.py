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


def _load_artifacts() -> None:
    """Charge tous les artefacts depuis le disque (lazy, thread-unsafe)."""
    global _model, _scaler, _qt, _feature_names

    if _model is not None:
        return  # déjà chargés

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


# Parsing de la chaine de version
# ------------------------------
# Le premier groupe est le major, les suivants sont optionnels
_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _parse_version(version_string: str) -> dict:
    """
    Extrait les composantes numeriques d'une chaine de version.

    Exemples acceptes :
        "Apache/2.4.41"  -> ma=2, mi=4, p=41, full=2.441
        "2.4"            -> ma=2, mi=4, p=0,  full=2.4
        "v2"             -> ma=2, mi=0, p=0,  full=2.0
        "openssl/1.1.1k" -> ma=1, mi=1, p=1,  full=1.11

    Valeurs par defaut si la chaine est malformee : tous a 0.
    """
    defaults = {"version_ma": 0, "version_mi": 0, "version_p": 0, "version_full": 0.0}

    if not version_string or not isinstance(version_string, str):
        return defaults

    m = _VERSION_RE.search(version_string)
    if not m:
        return defaults

    ma = int(m.group(1))
    mi = int(m.group(2)) if m.group(2) is not None else 0
    p  = int(m.group(3)) if m.group(3) is not None else 0

    # version_full = ma + 0.1*mi + 0.001*p  (ex: 2.4.41 -> 2.441)
    full = ma + mi * 0.1 + p * 0.001

    return {"version_ma": ma, "version_mi": mi, "version_p": p, "version_full": full}


# ──────────────────────────────────────────────────────────────
# API publique
# ──────────────────────────────────────────────────────────────
def predict(port: int, version_string: str, service: str = "", protocol: str = "tcp", os_hint: str = "") -> dict:
    """
    Prédit si un service réseau est vulnérable en utilisant 92 features.

    Paramètres
    ----------
    port           : numéro de port (ex : 80, 443, 22)
    version_string : chaîne de version brute (ex : "Apache/2.4.41")
    service        : nom du service détecté (ex : "Apache httpd")
    protocol       : protocole (tcp ou udp)
    os_hint        : indice sur l'OS (ex : "Ubuntu")

    Retourne
    --------
    dict avec les clés :
        - "vulnerable"  : int   → 0 ou 1
        - "confidence"  : float → probabilité de la classe prédite (0.0–1.0)
        - "label"       : str   → "VULNÉRABLE" ou "NON VULNÉRABLE"
    """
    _load_artifacts()

    # ── 1. Construction du vecteur brut ──────────────────────────
    # Initialisation de toutes les features à 0
    raw = {feat: 0 for feat in _feature_names}
    
    # Features de version
    version_feats = _parse_version(version_string)
    raw.update(version_feats)
    
    # Port
    raw["port"] = int(port) if port is not None else 0
    
    # ── 2. Encodage du service (One-Hot substring match) ──────────
    service_lower = service.lower() if service else ""
    for feat in _feature_names:
        if feat.startswith("service_"):
            service_name = feat.replace("service_", "")
            if service_name in service_lower:
                raw[feat] = 1
                
    # ── 3. Encodage du protocole ─────────────────────────────────
    if protocol.lower() == "tcp":
        raw["protocol_tcp"] = 1
        raw["protocol_udp"] = 0
    else:
        raw["protocol_tcp"] = 0
        raw["protocol_udp"] = 1
        
    # ── 4. Encodage de l'OS ──────────────────────────────────────
    os_lower = os_hint.lower() if os_hint else ""
    for feat in _feature_names:
        if feat.startswith("os_"):
            os_name = feat.replace("os_", "")
            if os_name in os_lower:
                raw[feat] = 1

    # ── 5. Transformation et Prédiction ───────────────────────────
    df = pd.DataFrame([raw], columns=_feature_names)

    # RobustScaler sur les colonnes numériques
    df[_SCALER_COLS] = _scaler.transform(df[_SCALER_COLS])

    # QuantileTransformer sur version_p et version_full
    df[_QT_COLS] = _qt.transform(df[_QT_COLS])

    # Prédiction
    prediction  = int(_model.predict(df[_feature_names])[0])
    probas      = _model.predict_proba(df[_feature_names])[0]
    confidence  = float(probas[prediction])

    label = "VULNÉRABLE" if prediction == 1 else "NON VULNÉRABLE"

    return {
        "vulnerable": prediction,
        "confidence": round(confidence, 4),
        "label":      label,
    }


# ──────────────────────────────────────────────────────────────
# Test rapide (python -m model.predictor)
# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_cases = [
        (80,  "Apache/2.4.41"),
        (443, "OpenSSL/1.0.1f"),
        (22,  "OpenSSH/7.4"),
        (21,  "vsftpd/2.3.4"),
        (80,  ""),               # version malformée → 0 par défaut
        (0,   None),             # port et version manquants
    ]

    print(f"{'Port':<6} {'Version':<25} {'Resultat':<18} {'Confiance':>9}")
    print("-" * 62)
    for port, ver in test_cases:
        result = predict(port, ver or "")
        # Use ASCII labels for test output to avoid encoding issues
        label = "VULNERABLE" if result['vulnerable'] == 1 else "NON VULNERABLE"
        print(
            f"{port:<6} {str(ver):<25} {label:<18} "
            f"{result['confidence']*100:>8.1f}%"
        )
