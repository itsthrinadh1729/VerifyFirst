"""Feature extraction for message detection."""
import re
from .schemas import MessageFeatures

# Regex patterns for feature extraction
URGENCY_PATTERNS = re.compile(
    r"\b(act now|immediately|urgent|within \d+ hours|last warning|action required|hurry|asap|do it now)\b",
    re.IGNORECASE
)

FINANCIAL_PATTERNS = re.compile(
    r"\b(send money|transfer|payment required|pay now|bank transfer|wire|funds|crypto|bitcoin|gift card)\b",
    re.IGNORECASE
)

CREDENTIAL_PATTERNS = re.compile(
    r"\b(enter your password|verify your password|verify your account|login to continue|confirm your credentials|sign in|account verification|account details)\b",
    re.IGNORECASE
)

OTP_PATTERNS = re.compile(
    r"\b(share otp|send verification code|tell me the pin|provide the code|verification pin|otp code|auth code|6-digit code|send me the otp|send the otp)\b",
    re.IGNORECASE
)

IMPERSONATION_PATTERNS = re.compile(
    r"\b(this is your bank|security team|whatsapp support|your account administrator|customer support|admin team|technical support|this is support)\b",
    re.IGNORECASE
)

THREAT_PATTERNS = re.compile(
    r"\b(account will be suspended|account will be blocked|account has been compromised|will be deactivated|unauthorized login attempt|security alert|account has a security problem)\b",
    re.IGNORECASE
)

PRIZE_PATTERNS = re.compile(
    r"\b(you won|congratulations|claim your prize|you have been selected|lottery|lucky winner|free gift|claim your reward)\b",
    re.IGNORECASE
)

CTA_PATTERNS = re.compile(
    r"\b(click here|verify now|claim now|open this link|complete verification|tap here|visit this link)\b",
    re.IGNORECASE
)

SOCIAL_ENGINEERING_PHRASES = re.compile(
    r"\b(do not tell anyone|keep this secret|don't share this|kindly help|i am in an emergency|trust me|confidential|don't contact anyone else)\b",
    re.IGNORECASE
)


def extract_features(message: str) -> MessageFeatures:
    """Extracts features from the given message content."""
    # Normalize whitespace (convert multiple spaces, tabs, newlines to single space)
    msg = re.sub(r'\s+', ' ', message).strip().lower()
    
    features = MessageFeatures(
        has_urgent_language=bool(URGENCY_PATTERNS.search(msg)),
        has_financial_request=bool(FINANCIAL_PATTERNS.search(msg)),
        has_credential_request=bool(CREDENTIAL_PATTERNS.search(msg)),
        has_otp_request=bool(OTP_PATTERNS.search(msg)),
        has_impersonation_language=bool(IMPERSONATION_PATTERNS.search(msg)),
        has_account_threat=bool(THREAT_PATTERNS.search(msg)),
        has_prize_claim=bool(PRIZE_PATTERNS.search(msg)),
        has_suspicious_cta=bool(CTA_PATTERNS.search(msg)),
    )
    
    # Social engineering pattern can be a mix of strong manipulative phrases 
    # OR a combination of other features.
    has_se_phrase = bool(SOCIAL_ENGINEERING_PHRASES.search(msg))
    
    # Combinations that denote social engineering:
    # Impersonation + Urgency
    # Threat + Urgency
    # Impersonation + Credential/OTP
    # Threat + Credential/OTP
    # Prize + Urgency + Financial
    combo_se = (
        (features.has_impersonation_language and features.has_urgent_language) or
        (features.has_account_threat and features.has_urgent_language) or
        (features.has_impersonation_language and (features.has_credential_request or features.has_otp_request)) or
        (features.has_account_threat and (features.has_credential_request or features.has_otp_request))
    )
    
    features.has_social_engineering_pattern = has_se_phrase or combo_se
    
    return features
