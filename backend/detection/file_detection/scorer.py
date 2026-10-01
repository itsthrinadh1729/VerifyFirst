"""File risk scoring and classification for VerifyFirst.

Aggregates rule evidence into a final risk score and classification.
Uses the same three-level model as URL detection (SAFE / SUSPICIOUS / DANGEROUS)
but with file-specific thresholds.
"""

from backend.detection.file_detection.schemas import (
    FileAnalysisInput,
    FileDetectionReason,
    FileDetectionResult,
)
from backend.detection.file_detection.features import extract_file_features
from backend.detection.file_detection.rules import evaluate_file_rules


def classify_file_risk_score(score: int) -> str:
    """Classify file risk score using the same thresholds as URL detection.

    - 0 - 25:   SAFE
    - 26 - 65:  SUSPICIOUS
    - 66 - 100: DANGEROUS

    Consistent thresholds ensure the Security Center treats both
    URL and file events uniformly.
    """
    if score <= 25:
        return "SAFE"
    elif score <= 65:
        return "SUSPICIOUS"
    else:
        return "DANGEROUS"


def analyze_file_security(input_data: FileAnalysisInput) -> FileDetectionResult:
    """Execute the file detection pipeline.

    FileAnalysisInput → Feature Extraction → Rule Evaluation →
    Score Aggregation & Clamping → Classification
    """
    features = extract_file_features(input_data)
    rule_results = evaluate_file_rules(features)

    triggered = [r for r in rule_results if r.triggered]
    raw_score = sum(r.weight for r in triggered)
    risk_score = min(100, max(0, raw_score))
    status = classify_file_risk_score(risk_score)

    reasons = [
        FileDetectionReason(rule=r.rule_id, message=r.message)
        for r in triggered
    ]

    return FileDetectionResult(
        status=status,
        risk_score=risk_score,
        reasons=reasons,
        filename=input_data.filename,
        asset_type="file",
    )
