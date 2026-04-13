import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import QuantileTransformer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import warnings
warnings.filterwarnings('ignore')
import joblib

# ─── 1. CHARGEMENT ───────────────────────────────────────────
df = pd.read_csv('dataset_model_normalized.csv', sep=';')

print(f"Lignes : {len(df)}")
print(f"Colonnes : {df.shape[1]}")
print(f"Vulnérables    : {df['vulnerable'].sum()} ({df['vulnerable'].mean()*100:.1f}%)")
print(f"Non vulnérables: {(df['vulnerable']==0).sum()} ({(df['vulnerable']==0).mean()*100:.1f}%)")

# ─── 2. RÉDUIRE LE POIDS DE version_p ET version_full ────────
qt = QuantileTransformer(output_distribution='normal', random_state=42)
df[['version_p', 'version_full']] = qt.fit_transform(df[['version_p', 'version_full']])
joblib.dump(qt, 'quantile_transformer.pkl')
print("✅ Poids de version_p et version_full réduits")

# ─── 3. SÉPARATION X et y ────────────────────────────────────
X = df.drop(columns=['vulnerable'])
y = df['vulnerable']

# ─── 4. DIVISION TRAIN / TEST ────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print(f"\nTrain : {len(X_train)} lignes")
print(f"Test  : {len(X_test)} lignes")

# ─── 5. ENTRAÎNEMENT ─────────────────────────────────────────
model = RandomForestClassifier(
    n_estimators=500,
    max_depth=25,
    min_samples_split=4,
    min_samples_leaf=2,
    max_features='sqrt',
    class_weight='balanced',
    bootstrap=True,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# ─── 6. ÉVALUATION ───────────────────────────────────────────
y_pred = model.predict(X_test)

print(f"\nAccuracy : {accuracy_score(y_test, y_pred):.4f}")
print("\nRapport de classification :")
print(classification_report(y_test, y_pred,
      target_names=['Non vulnérable', 'Vulnérable']))
print("Matrice de confusion :")
print(confusion_matrix(y_test, y_pred))

# ─── 7. IMPORTANCE DES FEATURES ──────────────────────────────
importances = pd.Series(
    model.feature_importances_,
    index=X.columns
).sort_values(ascending=False)

print("\nTop 10 des features les plus importantes :")
print(importances.head(10).to_string())

# ─── 8. PRÉDICTION EXEMPLE ───────────────────────────────────
sample = X_test.iloc[0:1]
proba  = model.predict_proba(sample)[0]
label  = model.predict(sample)[0]

print(f"\nSimulation :")
print(f"  Décision : {'⚠️ VULNÉRABLE' if label == 1 else '✅ NON VULNÉRABLE'}")
print(f"  Confiance : {max(proba)*100:.1f}%")

# ─── 9. SAUVEGARDE ───────────────────────────────────────────
joblib.dump(model, "vulnerability_model.pkl")
joblib.dump(X.columns.tolist(), "feature_names.pkl")

print("\n✅ Modèle sauvegardé : vulnerability_model.pkl")
print("✅ Features sauvegardées : feature_names.pkl")
print("✅ QuantileTransformer sauvegardé : quantile_transformer.pkl")