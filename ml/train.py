import os
import sys
import csv
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# Ensure backend can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.detection.features.extractor import extract_features, URLFeatures

def feature_to_array(f: URLFeatures) -> np.ndarray:
    """Convert URLFeatures into a numerical array."""
    return np.array([
        int(f.is_ip_address),
        f.url_length,
        f.host_length,
        f.num_subdomains,
        f.num_hyphens_host,
        int(f.has_at_symbol),
        f.num_dots_host,
        int(f.is_punycode),
        int(f.has_suspicious_encoding)
    ], dtype=float)

def load_data(csv_path: str):
    X = []
    y = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            lbl = row.get('label') or row.get('actual_label')
            if lbl == 'UNKNOWN':
                continue
            feats = extract_features(row['url'])
            X.append(feature_to_array(feats))
            y.append(1 if lbl == 'PHISHING' else 0)
    return np.array(X), np.array(y)

def train_model():
    csv_path = os.path.join(os.path.dirname(__file__), 'dataset', 'urls.csv')
    print(f"Loading training data from {csv_path}...")
    X_train, y_train = load_data(csv_path)
    
    print(f"Loaded {len(X_train)} samples ({sum(y_train)} PHISHING, {len(y_train)-sum(y_train)} SAFE).")
    
    print("Training RandomForestClassifier...")
    # Using a small number of estimators for prototype, fixing random state
    clf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
    clf.fit(X_train, y_train)
    
    model_dir = os.path.join(os.path.dirname(__file__), 'model')
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, 'rf_model.pkl')
    
    with open(model_path, 'wb') as f:
        pickle.dump(clf, f)
        
    print(f"Model saved to {model_path}.")
    
    # Feature importance
    feature_names = [
        "is_ip_address", "url_length", "host_length", "num_subdomains", 
        "num_hyphens_host", "has_at_symbol", "num_dots_host", 
        "is_punycode", "has_suspicious_encoding"
    ]
    print("\nFeature Importances:")
    importances = clf.feature_importances_
    for name, imp in sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True):
        print(f"  {name:<25}: {imp:.4f}")

if __name__ == "__main__":
    train_model()
