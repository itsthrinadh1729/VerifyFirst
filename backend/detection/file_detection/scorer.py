"""File risk scoring and classification for VerifyFirst.

Aggregates rule evidence into a final risk score and classification.
Uses the same three-level model as URL detection (SAFE / SUSPICIOUS / DANGEROUS)
with normalized scoring for continuous 0–100 distribution.
"""

from backend.detection.file_detection.schemas import (
    FileAnalysisInput,
    FileDetectionReason,
    FileDetectionResult,
)
from backend.detection.file_detection.features import extract_file_features
from backend.detection.file_detection.rules import evaluate_file_rules


# Calibrated normalization ceiling for file risk scoring.
#
# The theoretical sum of all file rule weights is ~235, but many rules
# are mutually exclusive (e.g., EXTENSION_MISMATCH_DECEPTION suppresses
# DANGEROUS_FILE_EXTENSION; DOUBLE_EXTENSION suppresses when mismatch fires).
# 105 represents the realistic maximum for a highly-suspicious file:
#   EXTENSION_MISMATCH_DECEPTION(70) + SOCIAL_ENGINEERING(15) +
#   MULTIPLE_EXTENSIONS(10) + EXCESSIVE_LENGTH(10) = 105
MAX_FILE_RAW_SCORE: int = 105


def normalize_file_risk_score(raw_score: int, max_raw: int) -> int:
    """Normalize a raw weight sum into a continuous 0–100 risk score.

    Formula: round(raw_score / max_raw * 100), clamped to [0, 100].
    """
    if max_raw <= 0:
        return min(100, max(0, raw_score))
    normalized = (raw_score / max_raw) * 100
    return max(0, min(100, round(normalized)))


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
    Score Aggregation → Normalization → Classification
    """
    features = extract_file_features(input_data)
    rule_results = evaluate_file_rules(features)

    triggered = [r for r in rule_results if r.triggered]
    raw_score = sum(r.weight for r in triggered)
    risk_score = normalize_file_risk_score(raw_score, MAX_FILE_RAW_SCORE)
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

