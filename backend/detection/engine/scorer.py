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


def analyze_url_security(url: str) -> DetectionResult:
    """Execute the deterministic detection pipeline on a validated URL:

    Validated URL -> Feature Extraction -> Rule Evaluation -> Score Aggregation & Clamping -> Classification
    """
    features = extract_features(url)
    rule_results = evaluate_rules(features)

    triggered = [r for r in rule_results if r.triggered]
    raw_score = sum(r.weight for r in triggered)
    risk_score = min(100, max(0, raw_score))
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
