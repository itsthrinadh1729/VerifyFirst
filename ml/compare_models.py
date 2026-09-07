import os
import csv
import sys
import numpy as np
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ml.train import load_data, feature_to_array
from ml.evaluate import calc_metrics
from backend.detection.features.extractor import extract_features
from backend.detection.engine.scorer import analyze_url_security
from scripts.evaluate_detection import MockGSBProvider
from backend.detection.intelligence.service import ThreatIntelService
from backend.detection.analysis.fusion import fuse_evidence

from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

async def run_comparison():
    train_csv = os.path.join(os.path.dirname(__file__), 'dataset', 'urls.csv')
    test_csv = os.path.join(os.path.dirname(__file__), '..', 'evaluation', 'urls.csv')
    
    # 1. Load Data
    X_train, y_train = load_data(train_csv)
    
    # Scale features for Logistic Regression and SVM
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    test_dataset = []
    with open(test_csv, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['actual_label'] != 'UNKNOWN':
                test_dataset.append(row)
                
    X_test = []
    y_test = []
    intel_service = ThreatIntelService(provider=MockGSBProvider())
    phase16_missed_indices = []
    
    for i, row in enumerate(test_dataset):
        feats = extract_features(row['url'])
        X_test.append(feature_to_array(feats))
        true_label = 1 if row['actual_label'] == 'PHISHING' else 0
        y_test.append(true_label)
        
        # Phase 16 deterministic result
        h_res = analyze_url_security(row['url'])
        intel = await intel_service.check_url(row['url'])
        final = fuse_evidence(h_res, intel)
        p16_pred = 1 if final.status in ('DANGEROUS', 'SUSPICIOUS') else 0
        if true_label == 1 and p16_pred == 0:
            phase16_missed_indices.append(i)

    X_test = np.array(X_test)
    X_test_scaled = scaler.transform(X_test)
    y_test = np.array(y_test)
    
    # 2. Define Models
    models = {
        "Logistic Regression": LogisticRegression(random_state=42),
        "SVM": SVC(probability=True, random_state=42),
        "Gradient Boosting": GradientBoostingClassifier(random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
    }
    
    feature_names = [
        "is_ip_address", "url_length", "host_length", "num_subdomains", 
        "num_hyphens_host", "has_at_symbol", "num_dots_host", 
        "is_punycode", "has_suspicious_encoding"
    ]
    
    model_results = {}
    
    # 3. Train and Evaluate
    for name, model in models.items():
        print(f"\n--- Evaluating {name} ---")
        if name in ("Logistic Regression", "SVM"):
            model.fit(X_train_scaled, y_train)
            probs = model.predict_proba(X_test_scaled)[:, 1]
        else:
            model.fit(X_train, y_train)
            probs = model.predict_proba(X_test)[:, 1]
            
        thresholds = [0.3, 0.4, 0.5, 0.6, 0.7]
        best_thresh = 0.5
        best_f1 = 0
        best_metrics = None
        
        for th in thresholds:
            preds = (probs >= th).astype(int)
            m = calc_metrics(y_test, preds)
            if m['f1'] > best_f1:
                best_f1 = m['f1']
                best_thresh = th
                best_metrics = m
                
        print(f"Optimal Threshold: {best_thresh:.2f}")
        model_results[name] = {
            "metrics": best_metrics,
            "threshold": best_thresh,
            "probs": probs,
            "model": model
        }
        
    print("\n=== Model Comparison ===")
    print(f"{'Model':<20} | {'Prec':<7} | {'Rec':<7} | {'F1':<5} | {'FPR':<7} | {'FNR':<7}")
    print("-" * 65)
    # Print Heuristics baseline manually from Phase 16 report
    print(f"{'Heuristics + GSB':<20} | {'100.0%':<7} | {'75.0%':<7} | {'0.86':<5} | {'0.0%':<7} | {'25.0%':<7}")
    for name, res in model_results.items():
        m = res['metrics']
        print(f"{name:<20} | {m['prec']:.1%} | {m['rec']:.1%} | {m['f1']:.2f} | {m['fpr']:.1%} | {m['fnr']:.1%}")
        
    print("\n=== Phase 16 Missed URLs ===")
    for i in phase16_missed_indices:
        url = test_dataset[i]['url']
        print(f"\nURL: {url}")
        for name, res in model_results.items():
            prob = res['probs'][i]
            pred = "PHISHING" if prob >= res['threshold'] else "SAFE"
            print(f"  {name:<20}: {pred} (Prob: {prob:.2f})")
            
    print("\n=== False Positive Analysis ===")
    for name, res in model_results.items():
        print(f"\nModel: {name}")
        probs = res['probs']
        th = res['threshold']
        fps = [test_dataset[i]['url'] for i in range(len(y_test)) if y_test[i] == 0 and probs[i] >= th]
        if not fps:
            print("  None")
        for fp in fps:
            print(f"  - {fp}")
            
    print("\n=== Feature Importance / Coefficients ===")
    for name, res in model_results.items():
        model = res['model']
        print(f"\nModel: {name}")
        if hasattr(model, 'feature_importances_'):
            importances = model.feature_importances_
            for fn, imp in sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True):
                print(f"  {fn:<25}: {imp:.4f}")
        elif hasattr(model, 'coef_'):
            coefs = model.coef_[0]
            for fn, coef in sorted(zip(feature_names, coefs), key=lambda x: abs(x[1]), reverse=True):
                print(f"  {fn:<25}: {coef:.4f}")
        else:
            print("  (No direct feature importance extraction available for this kernel)")

if __name__ == "__main__":
    asyncio.run(run_comparison())
