import sys
import os
import time

# Ajouter le dossier racine au path pour pouvoir importer le modèle
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model.predictor import predict

def run_reliability_test():
    print("=" * 60)
    print("TEST DE FIABILITÉ DU MODÈLE D'IA (VULNERABILITY PREDICTOR)")
    print("=" * 60)
    
    # Définition des cas de test : (Port, Version, Service, Label Attendu)
    # 1 = Vulnérable, 0 = Non Vulnérable
    test_cases = [
        # --- CAS VULNÉRABLES (Versions obsolètes ou connues pour CVEs) ---
        (80,  "Apache/2.4.49", "http", 1),       # CVE-2021-41773
        (443, "OpenSSL/1.0.1", "https", 1),      # Heartbleed
        (22,  "OpenSSH/7.2p2", "ssh", 1),        # User enumeration
        (21,  "vsftpd 2.3.4", "ftp", 1),         # Backdoor version
        (3306, "MySQL 5.1.73", "mysql", 1),      # Ancienne version
        (80,  "PHP/5.4.1", "http", 1),           # Obsolète
        (80,  "nginx/1.14.0", "http", 1),        # Ancienne version
        (25,  "Postfix 2.11.0", "smtp", 1),      # Ancienne version
        
        # --- CAS NON VULNÉRABLES (Versions récentes ou stables) ---
        (80,  "Apache/2.4.58", "http", 0),
        (443, "nginx/1.24.0", "https", 0),
        (22,  "OpenSSH/9.3", "ssh", 0),
        (3306, "MySQL/8.0.35", "mysql", 0),
        (80,  "PHP/8.2.12", "http", 0),
        (21,  "vsftpd/3.0.5", "ftp", 0),
        (25,  "Postfix/3.8.1", "smtp", 0),
        (443, "OpenSSL/3.1.0", "https", 0),
        
        # --- CAS AMBIGUS / NEUTRES ---
        (80,  "Non détectée", "http", 0),        # Devrait être traité comme sûr par défaut
        (8080, "SimpleHTTP/0.6", "http", 0),     # Version non listée comme critique
    ]

    print(f"Chargement du modèle (peut prendre quelques secondes car le fichier fait 5Go)...")
    start_load = time.time()
    # Le premier appel à predict chargera les artefacts
    predict(80, "test") 
    print(f"Modèle chargé en {time.time() - start_load:.2f} secondes.\n")

    results = []
    correct = 0
    total = len(test_cases)

    print(f"{'Service':<10} {'Version':<20} {'Attendu':<10} {'Prédit':<15} {'Confiance':<10} {'Statut':<10}")
    print("-" * 85)

    for port, version, service, expected in test_cases:
        prediction_dict = predict(port, version, service=service)
        
        predicted = prediction_dict['vulnerable']
        confidence = prediction_dict['confidence']
        
        expected_label = "VULN" if expected == 1 else "OK"
        predicted_label = "VULN" if predicted == 1 else "OK"
        
        is_correct = (predicted == expected)
        if is_correct:
            correct += 1
            status = "[PASS]"
        else:
            status = "[FAIL]"
            
        print(f"{service:<10} {version[:20]:<20} {expected_label:<10} {predicted_label:<15} {confidence*100:>7.1f}% {status:<10}")
        
        results.append({
            'expected': expected,
            'predicted': predicted,
            'correct': is_correct
        })

    accuracy = (correct / total) * 100
    
    # Calcul de précision et rappel simplifiés
    true_positives = sum(1 for r in results if r['expected'] == 1 and r['predicted'] == 1)
    false_positives = sum(1 for r in results if r['expected'] == 0 and r['predicted'] == 1)
    false_negatives = sum(1 for r in results if r['expected'] == 1 and r['predicted'] == 0)
    true_negatives = sum(1 for r in results if r['expected'] == 0 and r['predicted'] == 0)

    precision = (true_positives / (true_positives + false_positives)) * 100 if (true_positives + false_positives) > 0 else 0
    recall = (true_positives / (true_positives + false_negatives)) * 100 if (true_positives + false_negatives) > 0 else 0

    print("\n" + "=" * 60)
    print("RÉSULTATS DE L'ANALYSE")
    print("=" * 60)
    print(f"Nombre total de tests : {total}")
    print(f"Prédictions correctes : {correct}")
    print(f"Précision globale     : {accuracy:.2f}%")
    print(f"Precision (PPV)       : {precision:.2f}%")
    print(f"Rappel (Recall)       : {recall:.2f}%")
    print("-" * 60)
    
    if accuracy >= 90:
        print("Conclusion : Le modèle est EXCELLENT et très fiable.")
    elif accuracy >= 75:
        print("Conclusion : Le modèle est BON mais peut être affiné.")
    else:
        print("Conclusion : Le modèle nécessite un réentraînement ou plus de données.")
    print("=" * 60)

if __name__ == "__main__":
    run_reliability_test()
