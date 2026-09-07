import os
import pytest
import numpy as np
from ml.train import load_data, feature_to_array
from ml.evaluate import calc_metrics
from backend.detection.features.extractor import URLFeatures

# 17O - Automated tests for ML

def test_feature_to_array():
    f = URLFeatures(
        host="example.com",
        is_ip_address=False,
        url_length=20,
        host_length=11,
        num_subdomains=0,
        num_hyphens_host=0,
        has_at_symbol=False,
        num_dots_host=1,
        is_punycode=False,
        has_suspicious_encoding=False,
        registered_domain="example.com",
        hostname_tokens=["example", "com"]
    )
    arr = feature_to_array(f)
    assert len(arr) == 9
    assert isinstance(arr, np.ndarray)
    assert arr[1] == 20
    assert arr[7] == 0

def test_load_data():
    # Use the evaluation dataset which has known format
    csv_path = os.path.join(os.path.dirname(__file__), '..', 'evaluation', 'urls.csv')
    X, y = load_data(csv_path)
    
    assert len(X) > 0
    assert len(y) > 0
    assert len(X) == len(y)
    assert X.shape[1] == 9

def test_calc_metrics():
    y_true = [0, 1, 0, 1]
    y_pred = [0, 1, 1, 0]
    # TP: 1 (idx 1)
    # TN: 1 (idx 0)
    # FP: 1 (idx 2)
    # FN: 1 (idx 3)
    
    m = calc_metrics(y_true, y_pred)
    assert m['tp'] == 1
    assert m['fp'] == 1
    assert m['fn'] == 1
    assert m['tn'] == 1
    assert m['prec'] == 0.5
    assert m['rec'] == 0.5
    assert m['f1'] == 0.5
    assert m['fpr'] == 0.5
    assert m['fnr'] == 0.5
