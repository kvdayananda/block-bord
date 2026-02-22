import re

# High risk keywords (job scams, phishing)
HIGH_RISK_KEYWORDS = {
    "government job": 30,
    "job offer": 25,
    "verify account": 25,
    "urgent action": 20,
    "click here": 20,
    "otp": 25,
    "lottery": 30,
    "winner": 20,
    "free money": 30
}

MEDIUM_RISK_KEYWORDS = {
    "immediately": 10,
    "limited time": 10,
    "update details": 15,
    "bank account": 20
}

SUSPICIOUS_TLDS = {
    ".xyz": 25,
    ".click": 25,
    ".top": 20,
    ".gq": 25,
    ".tk": 25
}

def calculate_risk(text: str):
    risk_score = 0
    reasons = []
    text_lower = text.lower()

    # High risk keywords
    for keyword, weight in HIGH_RISK_KEYWORDS.items():
        if keyword in text_lower:
            risk_score += weight
            reasons.append(f"High-risk keyword detected: '{keyword}' (+{weight})")

    # Medium risk keywords
    for keyword, weight in MEDIUM_RISK_KEYWORDS.items():
        if keyword in text_lower:
            risk_score += weight
            reasons.append(f"Medium-risk keyword detected: '{keyword}' (+{weight})")

    # Suspicious TLD detection
    for tld, weight in SUSPICIOUS_TLDS.items():
        if tld in text_lower:
            risk_score += weight
            reasons.append(f"Suspicious domain detected: '{tld}' (+{weight})")

    # Email pattern detection
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    if re.search(email_pattern, text):
        risk_score += 5
        reasons.append("Contains email address (+5)")

    # Cap at 100
    risk_score = min(risk_score, 100)

    # Risk level classification
    if risk_score < 30:
        level = "SAFE"
    elif risk_score < 70:
        level = "SUSPICIOUS"
    else:
        level = "HIGH RISK"

    return {
        "risk_score": risk_score,
        "risk_level": level,
        "reasons": reasons
    }