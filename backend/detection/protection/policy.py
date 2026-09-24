from backend.detection.protection.schemas import ProtectionAction, ProtectionDecision
from backend.detection.engine.scorer import DetectionResult

def evaluate_protection_policy(result: DetectionResult) -> ProtectionDecision:
    """
    Evaluate the detection result to determine the appropriate protection action.
    This creates a strict separation between risk assessment and protection enforcement.
    """
    if result.status == "SAFE":
        return ProtectionDecision(action=ProtectionAction.ALLOW)
    elif result.status == "SUSPICIOUS":
        return ProtectionDecision(action=ProtectionAction.WARN)
    elif result.status == "DANGEROUS":
        return ProtectionDecision(action=ProtectionAction.BLOCK)
    else:
        # Fail safe for unknown status
        return ProtectionDecision(action=ProtectionAction.BLOCK)
