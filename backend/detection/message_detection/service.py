"""Message detection service for VerifyFirst."""
from .schemas import MessageAnalysisInput, MessageDetectionResult, MessageDetectionReason
from .features import extract_features
from .rules import evaluate_rules
from .scorer import calculate_score_and_status


def analyze_message(input_data: MessageAnalysisInput) -> MessageDetectionResult:
    """End-to-end message detection pipeline."""
    # 1. Extract Features
    features = extract_features(input_data.message)
    
    # 2. Evaluate Rules
    rules = evaluate_rules(features)
    
    # 3. Calculate Score and Classification
    score, status = calculate_score_and_status(rules)
    
    # 4. Construct Result
    reasons = [MessageDetectionReason(rule=r.rule_id, message=r.reason) for r in rules]
    
    return MessageDetectionResult(
        status=status,
        risk_score=score,
        reasons=reasons,
        asset_type="message"
    )
