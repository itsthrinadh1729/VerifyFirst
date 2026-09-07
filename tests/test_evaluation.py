import os
import pytest
from scripts.evaluate_detection import Evaluator

# 16P - Automated tests for the evaluation runner itself

def test_dataset_loads_correctly():
    csv_path = os.path.join(os.path.dirname(__file__), "..", "evaluation", "urls.csv")
    evaluator = Evaluator(csv_path)
    evaluator.load_dataset()
    
    # Dataset should not be empty
    assert len(evaluator.dataset) > 0
    
    # Check that labels are valid and UNKNOWN is excluded
    for row in evaluator.dataset:
        assert row['actual_label'] in ('SAFE', 'PHISHING')
        assert 'url' in row
        assert 'category' in row

def test_metrics_calculation():
    evaluator = Evaluator("dummy.csv")
    
    # Perfect predictions
    y_true = ['SAFE', 'PHISHING', 'SAFE', 'PHISHING']
    y_pred = ['SAFE', 'PHISHING', 'SAFE', 'PHISHING']
    
    metrics = evaluator._calc_metrics(y_true, y_pred, print_confusion=False)
    assert metrics['tp'] == 2
    assert metrics['tn'] == 2
    assert metrics['fp'] == 0
    assert metrics['fn'] == 0

    # Mixed predictions
    y_true_mixed = ['SAFE', 'PHISHING', 'SAFE', 'PHISHING']
    y_pred_mixed = ['PHISHING', 'PHISHING', 'SAFE', 'SAFE']
    # TP = 1, TN = 1, FP = 1, FN = 1
    
    metrics_mixed = evaluator._calc_metrics(y_true_mixed, y_pred_mixed, print_confusion=False)
    assert metrics_mixed['tp'] == 1
    assert metrics_mixed['tn'] == 1
    assert metrics_mixed['fp'] == 1
    assert metrics_mixed['fn'] == 1
