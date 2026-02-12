"""
Urgency & Threat Detection Module for the Honeypot System.
Detects pressure tactics, urgency indicators, and threat patterns.
"""

import re
from typing import Dict, List, Tuple


# Urgency indicators with severity weights
URGENCY_KEYWORDS = {
    # Critical urgency (weight 1.0)
    "immediately": 1.0, "right now": 1.0, "asap": 1.0,
    "within 1 hour": 1.0, "expire now": 1.0,
    # High urgency (weight 0.8)
    "today": 0.8, "urgent": 0.8, "now": 0.8, "hurry": 0.8,
    "within 24 hours": 0.8, "last chance": 0.8, "final notice": 0.8,
    "final warning": 0.8, "deadline": 0.8, "expires": 0.8,
    "time is running out": 0.8, "act fast": 0.8,
    # Medium urgency (weight 0.5)
    "soon": 0.5, "quickly": 0.5, "fast": 0.5,
    "as soon as possible": 0.5, "don't delay": 0.5,
    "time sensitive": 0.5, "limited time": 0.5,
    "must": 0.5, "need to": 0.5, "have to": 0.5,
    "required": 0.5, "mandatory": 0.5,
    # Low urgency (weight 0.3)
    "please do": 0.3, "kindly": 0.3, "at the earliest": 0.3,
    "action required": 0.3, "action needed": 0.3,
    # Hindi urgency
    "turant": 0.8, "abhi": 0.8, "jaldi": 0.7,
    "foran": 0.8, "tatkaal": 0.8,
}

# Threat indicators with severity weights
THREAT_KEYWORDS = {
    # Critical threats (weight 1.0)
    "arrested": 1.0, "jail": 1.0, "prison": 1.0,
    "warrant": 1.0, "fir": 1.0, "criminal case": 1.0,
    # High threats (weight 0.8)
    "blocked": 0.8, "suspended": 0.8, "frozen": 0.8,
    "closed": 0.8, "terminated": 0.8, "deactivated": 0.8,
    "legal action": 0.8, "court": 0.8, "police": 0.8,
    "blacklisted": 0.8, "permanently closed": 0.8,
    "legal proceedings": 0.8, "prosecution": 0.8,
    # Medium threats (weight 0.5)
    "fine": 0.5, "penalty": 0.5, "charges": 0.5,
    "restricted": 0.5, "disabled": 0.5, "locked": 0.5,
    "under investigation": 0.5, "suspicious activity": 0.5,
    "unauthorized": 0.5, "security breach": 0.5,
    # Low threats (weight 0.3)
    "problem": 0.3, "issue": 0.3, "risk": 0.3,
    "warning": 0.3, "alert": 0.3, "notice": 0.3,
    # Hindi threats
    "band": 0.8, "giraftar": 1.0, "jurmana": 0.5,
    "khatam": 0.7, "khatre": 0.5,
}

# Combined threat patterns (multi-word)
THREAT_PATTERNS = [
    (r"your\s+account\s+(?:will be|has been|is)\s+(?:blocked|suspended|frozen|closed|terminated)", 0.9),
    (r"(?:legal|police|court)\s+action\s+(?:will be|has been)\s+(?:taken|initiated)", 0.9),
    (r"(?:will|shall)\s+be\s+(?:arrested|prosecuted|penalized)", 1.0),
    (r"(?:fine|penalty)\s+of\s+(?:rs|inr|₹)?\s*\d+", 0.7),
    (r"(?:last|final)\s+(?:warning|notice|chance)", 0.8),
    (r"(?:failure|failing)\s+to\s+(?:comply|respond|act)", 0.7),
    (r"(?:within|before)\s+\d+\s+(?:hours?|minutes?|days?)", 0.7),
    (r"no\s+(?:more|further)\s+(?:time|delay|extension)", 0.8),
]

# Compiled patterns
_COMPILED_THREAT_PATTERNS = [(re.compile(p, re.IGNORECASE), w) for p, w in THREAT_PATTERNS]


def detect_urgency(message: str) -> Dict:
    """
    Detect urgency level in a message.

    Returns:
        Dict with urgency_level, urgency_score, and urgency_tactics
    """
    msg_lower = message.lower()
    tactics = []
    total_weight = 0.0
    count = 0

    for keyword, weight in URGENCY_KEYWORDS.items():
        if keyword in msg_lower:
            tactics.append(keyword)
            total_weight += weight
            count += 1

    # Normalize score (0-1)
    if count == 0:
        score = 0.0
    else:
        score = min(1.0, total_weight / 3.0)  # Cap at 1.0

    # Determine level
    if score >= 0.7:
        level = "high"
    elif score >= 0.35:
        level = "medium"
    else:
        level = "low"

    return {
        "urgency_level": level,
        "urgency_score": round(score, 3),
        "urgency_tactics": tactics,
    }


def detect_threats(message: str) -> Dict:
    """
    Detect threat level in a message.

    Returns:
        Dict with threat_level, threat_score, and threat_types
    """
    msg_lower = message.lower()
    threat_types = []
    total_weight = 0.0
    count = 0

    # Keyword matching
    for keyword, weight in THREAT_KEYWORDS.items():
        if keyword in msg_lower:
            threat_types.append(keyword)
            total_weight += weight
            count += 1

    # Pattern matching (adds more weight for complex threat patterns)
    for pattern, weight in _COMPILED_THREAT_PATTERNS:
        if pattern.search(message):
            total_weight += weight
            count += 1

    # Normalize score
    if count == 0:
        score = 0.0
    else:
        score = min(1.0, total_weight / 3.0)

    # Determine level
    if score >= 0.7:
        level = "high"
    elif score >= 0.35:
        level = "medium"
    else:
        level = "low"

    return {
        "threat_level": level,
        "threat_score": round(score, 3),
        "threat_types": threat_types,
    }


def analyze_pressure_tactics(message: str) -> Dict:
    """
    Combined analysis of urgency and threats.

    Returns:
        Full pressure analysis dict.
    """
    urgency = detect_urgency(message)
    threats = detect_threats(message)

    combined_score = (urgency["urgency_score"] * 0.45) + (threats["threat_score"] * 0.55)

    return {
        **urgency,
        **threats,
        "combined_pressure_score": round(combined_score, 3),
    }
