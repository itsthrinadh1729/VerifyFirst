import os
import pytest
import numpy as np
from ml.compare_models import load_data, feature_to_array, calc_metrics
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# 17B.12 - Automated tests for ML comparison

def test_models_can_train_and_predict():
    """Ensure all 4 models can train and predict on the extracted numerical features."""
    train_csv = os.path.join(os.path.dirname(__file__), '..', 'ml', 'dataset', 'urls.csv')
    X_train, y_train = load_data(train_csv)
    
    # Use a small subset containing both classes for quick testing
    X_subset = np.vstack((X_train[:10], X_train[-10:]))
    y_subset = np.concatenate((y_train[:10], y_train[-10:]))
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_subset)
    
    models = {
        "LR": LogisticRegression(random_state=42),
        "SVM": SVC(probability=True, random_state=42),
        "GBM": GradientBoostingClassifier(random_state=42),
        "RF": RandomForestClassifier(n_estimators=10, random_state=42)
    }
    
    for name, model in models.items():
        if name in ("LR", "SVM"):
            model.fit(X_train_scaled, y_subset)
            probs = model.predict_proba(X_train_scaled)
        else:
            model.fit(X_subset, y_subset)
            probs = model.predict_proba(X_subset)
            
        assert probs.shape == (20, 2)
        assert probs.max() <= 1.0
        assert probs.min() >= 0.0

def test_metrics_deterministic():
    y_true = [0, 1, 0, 1, 1, 0]
    y_pred = [0, 1, 1, 0, 1, 0]
    # TP: 2, FN: 1, FP: 1, TN: 2
    
    m1 = calc_metrics(y_true, y_pred)
    m2 = calc_metrics(y_true, y_pred)
    
    assert m1['f1'] == m2['f1']
    assert m1['fpr'] == m2['fpr']
    assert m1['prec'] == m2['prec']
