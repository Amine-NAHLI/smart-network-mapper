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
        # --- CAS COMPLEXES / EDGE CASES ---
        (22,   "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "ssh", 0), # Safe (Ubuntu patched)
        (80,   "Apache/2.2.8 (Win32) DAV/2", "http", 1),              # Very Old (VULN)
        (3128, "Squid proxy 2.7.STABLE9", "squid-http", 1),           # Ancient (VULN)
        (7001, "WebLogic Server 10.3.6.0", "weblogic", 1),           # Famous (VULN)
        (5984, "CouchDB/3.1.1 (Erlang OTP/23)", "couchdb", 0),        # Recent (OK)
        (1900, "MiniUPnPd/1.0", "upnp", 1),                           # Old (VULN)
        (4444, "Honeypot-Service v1.0", "honeypot", 0),               # Neutral (OK)
        (9999, "Unknown v99.99", "unknown", 0),                       # Future/Fake (OK)
        (80,   "nginx/1.1.19", "http", 1),                            # Old (VULN)
        (22,   "SSH-1.99-OpenSSH_3.4p1", "ssh", 1),                   # Ancient (VULN)
        
        # --- RÉCENTES / STABLES ---
        (80,   "Apache/2.4.58 (Unix)", "http", 0),
        (443,  "OpenSSL/3.2.0", "https", 0),
        (3306, "MySQL 8.1.0", "mysql", 0),
        (5432, "PostgreSQL 16.1", "postgres", 0),
        (6379, "Redis 7.2.3", "redis", 0),
        (80,   "Cloudflare", "http", 0),                              # WAF (OK)
        (22,   "SSH-2.0-dropbear_2022.82", "ssh", 0),                 # Recent (OK)
        (80,   "Go-http-server/1.1", "http", 0),                      # Internal (OK)
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
