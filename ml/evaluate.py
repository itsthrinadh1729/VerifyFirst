import os
import csv
import sys
import pickle
import numpy as np
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ml.train import feature_to_array, extract_features
from backend.detection.engine.scorer import analyze_url_security
from scripts.evaluate_detection import MockGSBProvider
from backend.detection.intelligence.service import ThreatIntelService
from backend.detection.analysis.fusion import fuse_evidence

def calc_metrics(y_true, y_pred, print_matrix=False):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)

    acc = (tp + tn) / len(y_true) if len(y_true) > 0 else 0
    prec = tp / (tp + fp) if tp + fp > 0 else 0
    rec = tp / (tp + fn) if tp + fn > 0 else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec > 0 else 0
    fpr = fp / (fp + tn) if fp + tn > 0 else 0
    fnr = fn / (tp + fn) if tp + fn > 0 else 0
    
    if print_matrix:
        print("\n  Confusion Matrix:")
        print("                 Actual")
        print("              SAFE   PHISHING")
        print(f"Pred SAFE      {tn:<4}     {fn:<4}")
        print(f"Pred PHISHING  {fp:<4}     {tp:<4}")

    return {"acc": acc, "prec": prec, "rec": rec, "f1": f1, "fpr": fpr, "fnr": fnr, 
            "tp": tp, "tn": tn, "fp": fp, "fn": fn}

async def evaluate_model():
    csv_path = os.path.join(os.path.dirname(__file__), '..', 'evaluation', 'urls.csv')
    model_path = os.path.join(os.path.dirname(__file__), 'model', 'rf_model.pkl')
    
    with open(model_path, 'rb') as f:
        clf = pickle.load(f)
        
    dataset = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['actual_label'] != 'UNKNOWN':
                dataset.append(row)
                
    X_test = []
    y_test = []
    
    # Phase 16 baseline evaluation on this test set
    intel_service = ThreatIntelService(provider=MockGSBProvider())
    phase16_missed_indices = []
    
    for i, row in enumerate(dataset):
        feats = extract_features(row['url'])
        X_test.append(feature_to_array(feats))
        true_label = 1 if row['actual_label'] == 'PHISHING' else 0
        y_test.append(true_label)
        
        # Calculate Phase 16 deterministic result
        h_res = analyze_url_security(row['url'])
        intel = await intel_service.check_url(row['url'])
        final = fuse_evidence(h_res, intel)
        p16_pred = 1 if final.status in ('DANGEROUS', 'SUSPICIOUS') else 0
        
        if true_label == 1 and p16_pred == 0:
            phase16_missed_indices.append(i)

    X_test = np.array(X_test)
    y_test = np.array(y_test)
    
    probs = clf.predict_proba(X_test)[:, 1] # Probability of PHISHING (class 1)
    
    print("=== Threshold Evaluation ===")
    thresholds = [0.3, 0.4, 0.5, 0.6, 0.7]
    best_thresh = 0.5
    best_f1 = 0
    
    for th in thresholds:
        preds = (probs >= th).astype(int)
        m = calc_metrics(y_test, preds)
        print(f"Threshold {th:.2f} | Prec: {m['prec']:.2%} | Rec: {m['rec']:.2%} | F1: {m['f1']:.2f} | FPR: {m['fpr']:.2%}")
        if m['f1'] > best_f1:
            best_f1 = m['f1']
            best_thresh = th
            
    print(f"\nOptimal threshold found: {best_thresh:.2f}")
    
    # Detailed output for best threshold
    final_preds = (probs >= best_thresh).astype(int)
    m = calc_metrics(y_test, final_preds, print_matrix=True)
    print(f"\nFinal ML Metrics at Threshold {best_thresh}:")
    print(f"  Accuracy:  {m['acc']:.2%}")
    print(f"  Precision: {m['prec']:.2%}")
    print(f"  Recall:    {m['rec']:.2%}")
    print(f"  F1 Score:  {m['f1']:.2f}")
    print(f"  FPR:       {m['fpr']:.2%}")
    print(f"  FNR:       {m['fnr']:.2%}")

    print("\n=== Did ML Catch Phase 16 Misses? ===")
    caught_count = 0
    for i in phase16_missed_indices:
        url = dataset[i]['url']
        prob = probs[i]
        ml_pred = "PHISHING" if prob >= best_thresh else "SAFE"
        print(f"URL: {url}")
        print(f"  ML Probability: {prob:.2f} -> {ml_pred}")
        if ml_pred == "PHISHING":
            caught_count += 1
    print(f"ML Caught {caught_count} / {len(phase16_missed_indices)} missed URLs.")
    
    print("\n=== ML False Positives (Legitimate flagged as Phishing) ===")
    fps = []
    for i in range(len(dataset)):
        if y_test[i] == 0 and final_preds[i] == 1:
            fps.append((dataset[i]['url'], probs[i]))
    if not fps:
        print("None")
    for fp in fps:
        print(f"URL: {fp[0]}, Prob: {fp[1]:.2f}")
        
    print("\n=== ML False Negatives (Phishing missed by ML) ===")
    fns = []
    for i in range(len(dataset)):
        if y_test[i] == 1 and final_preds[i] == 0:
            fns.append((dataset[i]['url'], probs[i]))
    if not fns:
        print("None")
    for fn in fns:
        print(f"URL: {fn[0]}, Prob: {fn[1]:.2f}")


if __name__ == "__main__":
    asyncio.run(evaluate_model())
