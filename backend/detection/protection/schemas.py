from enum import Enum
from dataclasses import dataclass

class ProtectionAction(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"

@dataclass(frozen=True)
class ProtectionDecision:
    """The final protection action determined by the policy engine."""
    action: ProtectionAction
