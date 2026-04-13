import pandas as pd
from sklearn.preprocessing import RobustScaler
import joblib

# ─── CHARGEMENT ──────────────────────────────────────────────
df = pd.read_csv('dataset_model.csv', sep=';', engine='python')
print(f"✅ Données chargées : {len(df)} lignes, {df.shape[1]} colonnes")

# ─── CORRECTION DES VALEURS SCIENTIFIQUES ────────────────────
cols_to_fix = ['version_mi', 'version_full']
for col in cols_to_fix:
    df[col] = df[col].astype(str).str.replace(',', '.', regex=False)
    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
print("✅ Valeurs scientifiques corrigées")

# ─── NORMALISATION ───────────────────────────────────────────
cols_to_scale = ['version_ma', 'version_mi', 'version_p', 
                 'version_full', 'port']

scaler = RobustScaler()
df[cols_to_scale] = scaler.fit_transform(df[cols_to_scale])
print("✅ Normalisation appliquée")

# ─── SAUVEGARDE CSV NORMALISÉ ────────────────────────────────
df.to_csv('dataset_model_normalized.csv', sep=';', index=False)
print("✅ CSV sauvegardé : dataset_model_normalized.csv")

# ─── SAUVEGARDE SCALER ───────────────────────────────────────
joblib.dump(scaler, 'scaler.pkl')
print("✅ Scaler sauvegardé : scaler.pkl")