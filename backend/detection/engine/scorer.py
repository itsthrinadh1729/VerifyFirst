"""Detection engine: score aggregation and risk classification."""

from dataclasses import dataclass, field
from backend.detection.features.extractor import extract_features
from backend.detection.rules.rules import evaluate_rules


@dataclass(frozen=True)
class DetectionReason:
    """Structured detection reason with rule ID and explanation."""

    rule: str
    message: str


@dataclass(frozen=True)
class DetectionResult:
    """Aggregated security detection result."""

    status: str
    risk_score: int
    reasons: list[DetectionReason] = field(default_factory=list)


def classify_risk_score(score: int) -> str:
    """Classify risk score according to approved baseline thresholds:

    - 0 - 25:   SAFE
    - 26 - 65:  SUSPICIOUS
    - 66 - 100: DANGEROUS
    """
    if score <= 25:
        return "SAFE"
    elif score <= 65:
        return "SUSPICIOUS"
    else:
        return "DANGEROUS"


# Calibrated normalization ceiling for URL risk scoring.
#
# This is NOT the theoretical sum of all rule weights (315), because many
# rules are mutually exclusive (e.g., IP_ADDRESS_HOST and BRAND_IMPERSONATION
# rarely co-occur on the same URL). Instead, 130 represents the realistic
# maximum raw score a highly-suspicious URL can achieve through the
# heuristic pipeline. This preserves meaningful classification boundaries:
#   - Single strong indicator (35 raw) → ~27 normalized → SUSPICIOUS
#   - Two strong indicators (65 raw)   → ~50 normalized → SUSPICIOUS
#   - Multi-indicator phishing (90+ raw) → 69+ normalized → DANGEROUS
MAX_RAW_SCORE: int = 130


def normalize_risk_score(raw_score: int, max_raw: int) -> int:
    """Normalize a raw weight sum into a continuous 0–100 risk score.

    Formula: round(raw_score / max_raw * 100), clamped to [0, 100].

    This produces a continuous distribution instead of quantized values
    that mirror individual rule weights.
    """
    if max_raw <= 0:
        return min(100, max(0, raw_score))
    normalized = (raw_score / max_raw) * 100
    return max(0, min(100, round(normalized)))


def analyze_url_security(url: str) -> DetectionResult:
    """Execute the deterministic detection pipeline on a validated URL:

    Validated URL -> Feature Extraction -> Rule Evaluation -> Score Aggregation -> Normalization -> Classification
    """
    features = extract_features(url)
    rule_results = evaluate_rules(features)

    triggered = [r for r in rule_results if r.triggered]
    raw_score = sum(r.weight for r in triggered)
    risk_score = normalize_risk_score(raw_score, MAX_RAW_SCORE)
    status = classify_risk_score(risk_score)

    reasons = [
        DetectionReason(rule=r.rule_id, message=r.message)
        for r in triggered
    ]

    return DetectionResult(
        status=status,
        risk_score=risk_score,
        reasons=reasons,
    )
