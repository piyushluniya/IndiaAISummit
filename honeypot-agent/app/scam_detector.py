"""
Enhanced Multi-Layer Scam Detection Module for the Honeypot System.

4-Layer Detection:
  Layer 1 - Keyword scoring (100+ terms)
  Layer 2 - Pattern matching (multi-word scam patterns)
  Layer 3 - Context analysis (conversation history)
  Layer 4 - Feature scoring (structural indicators)

Plus ML classifier + LLM verification.
"""

import re
from typing import List, Dict, Optional, Tuple
from .models import ScamDetectionResult
from .config import logger, settings
from .urgency_detector import analyze_pressure_tactics

# Import ML classifier
try:
    from .ml_classifier import get_ml_prediction
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logger.warning("ML classifier not available, using enhanced fallback")


# ══════════════════════════════════════════════════════════════════════
# LAYER 1: KEYWORD SCORING (100+ terms)
# ══════════════════════════════════════════════════════════════════════

HIGH_RISK_KEYWORDS = {
    # Bank fraud
    "blocked": 10, "suspended": 10, "frozen": 10, "verify": 8,
    "kyc": 9, "account closed": 10, "deactivated": 10, "unauthorized": 9,
    "security alert": 9, "fraud alert": 9, "account will be": 10,
    "account has been": 10, "unusual activity": 9, "suspicious activity": 9,
    "avoid suspension": 9, "to avoid": 6,
    # UPI fraud
    "upi": 7, "paytm": 6, "phonepe": 6, "gpay": 6, "google pay": 6,
    "send money": 9, "transfer money": 9, "payment request": 8,
    "receive money": 7, "bhim": 6,
    # OTP theft
    "otp": 10, "verification code": 10, "one time password": 10,
    "pin": 8, "cvv": 10, "password": 8, "share otp": 10, "send otp": 10,
    "share pin": 10, "atm pin": 10, "mpin": 9,
    # Urgency
    "urgent": 8, "immediately": 9, "right now": 9, "within 24 hours": 8,
    "expire": 8, "last chance": 9, "final notice": 9, "final warning": 9,
    "act fast": 8, "hurry": 7, "time is running out": 8,
    # Authority impersonation
    "rbi": 9, "reserve bank": 9, "income tax": 9, "government": 8,
    "police": 9, "legal action": 9, "court": 8, "officer": 7,
    "cyber cell": 9, "crime branch": 9, "customs": 8,
    # Threats
    "arrested": 10, "jail": 10, "fir": 10, "penalty": 8,
    "fine": 7, "blacklisted": 8, "warrant": 10,
    "legal proceedings": 9, "criminal case": 10,
    # Prizes/lottery
    "won": 7, "lottery": 9, "prize": 8, "reward": 7,
    "cashback": 6, "refund": 7, "selected": 6, "lucky": 7,
    "congratulations": 7, "winner": 8, "claim": 8,
    # Investment
    "investment": 7, "guaranteed returns": 9, "double money": 10,
    "high returns": 8, "profit": 6, "scheme": 7,
    "easy money": 9, "quick money": 9,
    # Job scam
    "work from home": 7, "part time job": 7, "earn from home": 8,
    "registration fee": 9, "advance payment": 9,
    # Action words
    "click here": 8, "click link": 8, "click below": 8,
    "visit link": 8, "open link": 8, "update details": 8,
    "verify identity": 9, "confirm identity": 9, "submit": 6,
    # Electricity/utility
    "electricity": 6, "disconnected": 8, "power cut": 8, "overdue bill": 8,
    "outstanding bill": 7, "meter reading": 5,
    # Customs/parcel
    "parcel": 6, "customs duty": 8, "seized": 8, "detained": 8,
    "shipment": 5, "courier": 5, "clearance fee": 8,
    # Insurance
    "insurance": 5, "policy": 5, "premium": 5, "matured": 7,
    "lapsed": 7, "claim amount": 7,
    # Loan
    "pre-approved": 8, "loan": 5, "sanctioned": 7, "emi": 5,
    "processing fee": 9, "stamp duty": 7,
    # Crypto
    "crypto": 6, "bitcoin": 6, "ethereum": 6, "mining": 6,
    "staking": 6, "nft": 5, "token": 4,
    # Government scheme
    "subsidy": 6, "yojana": 7, "aadhaar": 6, "pm kisan": 7,
    "benefit": 4, "grant": 5,
    # Tech support
    "virus": 7, "malware": 8, "hacked": 8, "compromised": 8,
    "antivirus": 6, "remote access": 9,
    # Hindi keywords
    "khata band": 10, "turant": 8, "sत्यापित": 8,
}

MEDIUM_RISK_KEYWORDS = {
    "confirm": 4, "account": 3, "bank": 3, "payment": 4,
    "transfer": 4, "update": 3, "details": 3, "information": 3,
    "card": 4, "link": 4, "register": 3, "activate": 4,
    "form": 3, "process": 3, "amount": 3, "transaction": 4,
    "balance": 3, "statement": 3, "customer care": 5,
    "support team": 5, "helpline": 4, "toll free": 4,
    "whatsapp": 3, "telegram": 3, "offer": 3, "deal": 3,
    "limited": 3, "special": 3, "exclusive": 3,
    # Utility/bills
    "overdue": 5, "pending": 4, "outstanding": 4, "unpaid": 5,
    "disconnect": 5, "due date": 4,
    # Parcel/customs
    "delivery": 3, "tracking": 3, "warehouse": 3,
    # Insurance/loan
    "maturity": 4, "nominee": 3, "beneficiary": 3, "disburse": 4,
    # General scam indicators
    "selected": 4, "eligible": 4, "entitled": 4, "receive": 3,
    "collect": 4, "avail": 3, "complimentary": 4,
}


def _keyword_score(message: str) -> Tuple[float, List[str]]:
    """Layer 1: Keyword-based scoring. Returns (normalized_score, matched_keywords)."""
    msg_lower = message.lower()
    total = 0
    matched = []

    for kw, weight in HIGH_RISK_KEYWORDS.items():
        if kw in msg_lower:
            total += weight
            matched.append(kw)

    for kw, weight in MEDIUM_RISK_KEYWORDS.items():
        if kw in msg_lower:
            total += weight
            matched.append(kw)

    # Normalize: 30+ points = 1.0
    normalized = min(1.0, total / 30.0)
    return normalized, matched


# ══════════════════════════════════════════════════════════════════════
# LAYER 2: PATTERN MATCHING
# ══════════════════════════════════════════════════════════════════════

SCAM_PATTERNS = [
    # Bank impersonation
    (r"(?:your|the)\s+(?:bank\s+)?account\s+(?:will be|has been|is being|is)\s+(?:blocked|suspended|frozen|closed|terminated|deactivated)", "bank_impersonation", 0.9),
    (r"(?:bank|rbi|sbi|hdfc|icici|axis)\s+(?:officer|manager|executive|representative)\s+(?:here|calling|speaking)", "bank_impersonation", 0.8),
    (r"(?:dear|respected)\s+(?:customer|account holder|sir|madam)", "bank_impersonation", 0.5),
    (r"(?:unusual|suspicious)\s+(?:activity|transaction)\s+(?:on|in|detected)", "bank_impersonation", 0.7),
    (r"(?:verify|confirm|update)\s+(?:your)?\s*(?:details|identity|information)\s+(?:to avoid|or|otherwise)", "bank_impersonation", 0.7),

    # UPI fraud
    (r"(?:send|transfer|pay)\s+(?:money|amount|rs|₹|inr)\s+(?:to|via|through)\s+(?:upi|paytm|phonepe|gpay)", "upi_fraud", 0.9),
    (r"(?:upi|paytm|phonepe|gpay)\s+(?:id|number)\s*[:=]?\s*\w+@\w+", "upi_fraud", 0.85),
    (r"(?:scan|use)\s+(?:this|the)\s+(?:qr|upi)\s+(?:code|link)", "upi_fraud", 0.8),

    # OTP theft
    (r"(?:share|send|give|tell|provide)\s+(?:me|us)?\s*(?:the|your)?\s*(?:otp|verification code|one time password|pin|mpin)", "otp_theft", 0.95),
    (r"(?:otp|code|pin)\s+(?:sent|received|generated)\s+(?:to|on)\s+(?:your|the)\s+(?:phone|mobile|number)", "otp_theft", 0.7),

    # Phishing
    (r"(?:click|open|visit|go to)\s+(?:this|the|below)?\s*(?:link|url|website)", "phishing_link", 0.8),
    (r"(?:https?://|bit\.ly|tinyurl|goo\.gl)", "phishing_link", 0.6),

    # Investment scam
    (r"(?:guaranteed|assured|fixed)\s+(?:returns?|profit|income)", "investment_scam", 0.9),
    (r"(?:double|triple|multiply)\s+(?:your)?\s*(?:money|investment|amount)", "investment_scam", 0.95),
    (r"(?:invest|deposit)\s+(?:rs|₹|inr)?\s*\d+\s+(?:and|to)\s+(?:get|earn|receive)", "investment_scam", 0.85),

    # Job scam
    (r"(?:work|earn|job)\s+(?:from|at)\s+home", "job_scam", 0.6),
    (r"(?:registration|processing|admission)\s+fee", "job_scam", 0.8),
    (r"(?:earn|make)\s+(?:rs|₹|inr)?\s*\d+\s*(?:per|every|daily|weekly)", "job_scam", 0.7),

    # KYC update scam
    (r"(?:kyc|know your customer)\s+(?:update|verification|expired|pending|mandatory)", "kyc_update", 0.85),
    (r"(?:complete|update)\s+(?:your)?\s*kyc\s+(?:immediately|now|today|urgently)", "kyc_update", 0.9),

    # Prize/lottery scam
    (r"(?:you have|you've|you)\s+(?:won|been selected|been chosen)\s+(?:a|the)?\s*(?:prize|lottery|reward|gift|cashback)", "prize_lottery", 0.9),
    (r"(?:claim|collect|receive)\s+(?:your)?\s*(?:prize|reward|winnings|gift)", "prize_lottery", 0.85),

    # Tax/legal scam
    (r"(?:income tax|it department|tax department)\s+(?:notice|alert|warning|action)", "tax_legal", 0.85),
    (r"(?:legal|court|police)\s+(?:action|notice|case)\s+(?:will be|has been|against)", "tax_legal", 0.9),
    (r"(?:arrest|fir|warrant)\s+(?:will be|has been|issued)", "tax_legal", 0.95),

    # Refund scam
    (r"(?:refund|cashback|reimbursement)\s+(?:of|worth)?\s*(?:rs|₹|inr)?\s*\d+", "refund_scam", 0.7),
    (r"(?:process|initiate|complete)\s+(?:your)?\s*(?:refund|cashback)", "refund_scam", 0.75),

    # Tech support scam
    (r"(?:virus|malware|hacked|compromised)\s+(?:detected|found|in your)", "tech_support", 0.8),
    (r"(?:install|download)\s+(?:this|the)\s+(?:app|software|antivirus)", "tech_support", 0.75),

    # Electricity/utility bill scam
    (r"(?:electricity|power|gas|water)\s+(?:bill|connection|supply)\s+(?:.*?\s+)?(?:overdue|unpaid|disconnected|pending|due)", "electricity_bill", 0.85),
    (r"(?:electricity|power|gas|water)\s+(?:.*?\s+)?(?:will be|be)\s+(?:disconnected|cut|terminated|stopped)", "electricity_bill", 0.9),
    (r"(?:disconnect|cut off|terminate)\s+(?:your)?\s*(?:electricity|power|gas|water|connection)", "electricity_bill", 0.9),
    (r"(?:pay|clear)\s+(?:your)?\s*(?:outstanding|pending|overdue)\s+(?:bill|dues|amount)", "electricity_bill", 0.7),
    (r"(?:bill|dues)\s+(?:is|are)?\s*(?:overdue|pending|unpaid|outstanding)", "electricity_bill", 0.75),

    # Government scheme scam
    (r"(?:government|govt|pm|pradhan mantri)\s+(?:scheme|yojana|subsidy|benefit|grant)", "govt_scheme", 0.8),
    (r"(?:eligible|selected|entitled)\s+(?:for|to)\s+(?:a|the)?\s*(?:subsidy|benefit|grant|scheme|relief)", "govt_scheme", 0.85),
    (r"(?:aadhaar|aadhar)\s+(?:linked|verified|required|update)", "govt_scheme", 0.6),

    # Crypto/investment scam
    (r"(?:crypto|bitcoin|ethereum|nft|token)\s+(?:investment|trading|profit|opportunity)", "crypto_investment", 0.85),
    (r"(?:guaranteed|assured|minimum)\s+(?:\d+%|\d+x)\s+(?:returns?|profit|gains?)", "crypto_investment", 0.9),
    (r"(?:mining|staking|defi)\s+(?:pool|platform|opportunity|profit)", "crypto_investment", 0.8),

    # Customs/parcel scam
    (r"(?:customs|parcel|package|courier|shipment)\s+(?:held|seized|detained|stuck|pending)", "customs_parcel", 0.85),
    (r"(?:release|clear|collect)\s+(?:your)?\s*(?:parcel|package|shipment|goods)", "customs_parcel", 0.8),
    (r"(?:customs|import)\s+(?:duty|fee|tax|charge|clearance)", "customs_parcel", 0.75),

    # Insurance scam
    (r"(?:insurance|policy)\s+(?:.*?\s+)?(?:claim|premium|expired|lapsed|matured|bonus)", "insurance", 0.8),
    (r"(?:policy|insurance)\s+(?:.*?\s+)?(?:has|is)\s+(?:matured|expired|lapsed)", "insurance", 0.85),
    (r"(?:claim|collect)\s+(?:your)?\s*(?:insurance|policy|amount|benefit|maturity|bonus)", "insurance", 0.85),
    (r"(?:policy|insurance)\s+(?:no\.?|number|id)\s*[:.]?\s*[A-Za-z0-9]", "insurance", 0.6),

    # Loan approval scam
    (r"(?:loan|credit)\s+(?:approved|sanctioned|pre-approved|eligible|offer)", "loan_approval", 0.8),
    (r"(?:pre-approved|instant|guaranteed)\s+(?:loan|credit|financing)", "loan_approval", 0.85),
    (r"(?:processing|documentation|stamp duty)\s+fee\s+(?:of|for|rs|₹)", "loan_approval", 0.8),
]

_COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE), t, w) for p, t, w in SCAM_PATTERNS]


def _pattern_score(message: str) -> Tuple[float, List[str], List[str]]:
    """Layer 2: Pattern matching. Returns (score, scam_types, patterns_found)."""
    types = set()
    patterns_found = []
    max_score = 0.0

    for pattern, scam_type, weight in _COMPILED_PATTERNS:
        if pattern.search(message):
            types.add(scam_type)
            patterns_found.append(f"{scam_type}:{weight}")
            max_score = max(max_score, weight)

    # Boost if multiple types detected
    if len(types) >= 2:
        max_score = min(1.0, max_score + 0.1)

    return max_score, list(types), patterns_found


# ══════════════════════════════════════════════════════════════════════
# LAYER 3: CONTEXT ANALYSIS
# ══════════════════════════════════════════════════════════════════════

def _context_score(
    message: str,
    conversation_history: List[Dict] = None,
    session_id: str = None,
) -> float:
    """Layer 3: Conversation context analysis."""
    if not conversation_history:
        return 0.0

    score = 0.0
    scammer_msgs = [
        m.get("text", "").lower()
        for m in conversation_history
        if m.get("sender", "").lower() in ("scammer", "unknown")
    ]

    if not scammer_msgs:
        return 0.0

    # Escalating threats check
    threat_counts = []
    for msg in scammer_msgs:
        count = sum(1 for kw in ["block", "suspend", "legal", "arrest", "urgent", "immediately"]
                    if kw in msg)
        threat_counts.append(count)

    if len(threat_counts) >= 2:
        if threat_counts[-1] > threat_counts[0]:
            score += 0.3  # Escalating

    # Repeated info requests
    info_keywords = ["otp", "upi", "account", "password", "pin", "card", "cvv"]
    info_request_count = 0
    for msg in scammer_msgs:
        if any(kw in msg for kw in info_keywords):
            info_request_count += 1

    if info_request_count >= 2:
        score += 0.25

    # Trust building then money request
    has_trust = any(
        any(w in msg for w in ["bank", "officer", "government", "rbi", "official"])
        for msg in scammer_msgs[:3]
    )
    has_money = any(
        any(w in msg for w in ["send", "pay", "transfer", "upi", "amount"])
        for msg in scammer_msgs[2:]
    )
    if has_trust and has_money:
        score += 0.3

    # Contradiction detection (claims different organizations)
    orgs_mentioned = set()
    for msg in scammer_msgs:
        for org in ["sbi", "hdfc", "icici", "axis", "rbi", "police", "income tax", "customs"]:
            if org in msg:
                orgs_mentioned.add(org)
    if len(orgs_mentioned) >= 3:
        score += 0.2  # Suspicious: mentions too many orgs

    return min(1.0, score)


# ══════════════════════════════════════════════════════════════════════
# LAYER 4: FEATURE SCORING
# ══════════════════════════════════════════════════════════════════════

# Regex for structural features
_HAS_PHONE = re.compile(r'(?:\+91|91|0)?[6-9]\d{9}')
_HAS_UPI = re.compile(r'\w+@\w+', re.IGNORECASE)
_HAS_LINK = re.compile(r'https?://|bit\.ly|tinyurl|goo\.gl|\w+\[dot\]\w+', re.IGNORECASE)
_HAS_AMOUNT = re.compile(r'(?:₹|rs\.?|inr)\s*[\d,]+', re.IGNORECASE)

URGENCY_WORDS = {"urgent", "immediately", "now", "today", "hurry", "asap", "fast", "quickly", "right now", "last chance", "final"}
AUTHORITY_WORDS = {"bank", "rbi", "government", "police", "income tax", "officer", "court", "legal", "customs", "cyber cell"}
THREAT_WORDS = {"blocked", "suspended", "arrested", "fir", "jail", "penalty", "fine", "legal action", "warrant", "terminated", "suspension", "deactivated", "frozen"}
SENSITIVE_INFO_WORDS = {"otp", "pin", "cvv", "password", "account number", "card number", "aadhaar", "pan", "verify your details", "verify your identity", "confirm your details", "update your details"}


def _feature_score(message: str) -> Tuple[float, List[str]]:
    """Layer 4: Feature-based scoring. Returns (score, red_flags)."""
    msg_lower = message.lower()
    score = 0.0
    red_flags = []

    # Has urgency words
    if any(w in msg_lower for w in URGENCY_WORDS):
        score += 0.3
        red_flags.append("urgency_detected")

    # Contains phone/UPI/account
    if _HAS_PHONE.search(message) or _HAS_UPI.search(message):
        score += 0.2
        red_flags.append("contact_info_present")

    # Contains link
    if _HAS_LINK.search(message):
        score += 0.25
        red_flags.append("link_detected")

    # Impersonates authority
    if any(w in msg_lower for w in AUTHORITY_WORDS):
        score += 0.3
        red_flags.append("authority_impersonation")

    # Requests sensitive info
    if any(w in msg_lower for w in SENSITIVE_INFO_WORDS):
        score += 0.4
        red_flags.append("sensitive_info_request")

    # Contains threat
    if any(w in msg_lower for w in THREAT_WORDS):
        score += 0.35
        red_flags.append("threat_detected")

    # Money amount mentioned
    if _HAS_AMOUNT.search(message):
        score += 0.15
        red_flags.append("money_amount_mentioned")

    return min(1.0, score), red_flags


# ══════════════════════════════════════════════════════════════════════
# HYBRID DETECTOR
# ══════════════════════════════════════════════════════════════════════

class HybridScamDetector:
    """
    Multi-layer scam detection combining:
    - Keyword scoring
    - Pattern matching
    - Context analysis
    - Feature scoring
    - ML classifier
    - LLM verification
    """

    def __init__(self):
        self.suspicious_count: Dict[str, int] = {}
        self.gemini_model = None
        logger.info("HybridScamDetector initialized (enhanced multi-layer)")

    def analyze(
        self,
        message: str,
        session_id: str = None,
        conversation_history: List[Dict] = None,
    ) -> ScamDetectionResult:
        """Analyze a message using all detection layers."""

        # Handle edge cases
        if not message or not message.strip():
            return ScamDetectionResult(
                is_scam=False, confidence=0.0, risk_score=0,
                detected_patterns=[], scam_types=[],
            )

        # Normalize
        clean_msg = message.strip()

        # Very short messages: use lighter analysis
        if len(clean_msg.split()) < 3:
            return self._analyze_short_message(clean_msg)

        # ── Layer 1: Keywords ──
        kw_score, kw_matched = _keyword_score(clean_msg)

        # ── Layer 2: Patterns ──
        pat_score, scam_types, patterns_found = _pattern_score(clean_msg)

        # ── Layer 3: Context ──
        ctx_score = _context_score(clean_msg, conversation_history, session_id)

        # ── Layer 4: Features ──
        feat_score, red_flags = _feature_score(clean_msg)

        # ── ML layer ──
        ml_probs = self._get_ml_probs(clean_msg)

        # ── Weighted combination ──
        rule_score = (
            kw_score * 0.30
            + pat_score * 0.30
            + ctx_score * 0.20
            + feat_score * 0.20
        )

        # Blend with ML — rules dominate since ML may not cover all 15 scam types
        ml_scam = ml_probs.get("scam", 0.0)
        final_confidence = (rule_score * 0.75) + (ml_scam * 0.25)

        # Pressure tactics analysis
        pressure = analyze_pressure_tactics(clean_msg)
        urgency_level = pressure["urgency_level"]
        threat_level = pressure["threat_level"]

        # Boost if pressure is high
        if pressure["combined_pressure_score"] > 0.5:
            final_confidence = min(1.0, final_confidence + 0.1)

        # Decision — lower threshold for honeypot (false positives are fine, false negatives lose 20pts)
        is_scam = final_confidence > 0.35

        # Track suspicious turns
        if session_id:
            if final_confidence > 0.3:
                self.suspicious_count[session_id] = self.suspicious_count.get(session_id, 0) + 1
            elif final_confidence < 0.15:
                self.suspicious_count[session_id] = 0

        # Build detected patterns list
        all_patterns = patterns_found.copy()
        if kw_matched:
            all_patterns.append(f"keywords:{len(kw_matched)}")
        all_patterns.append(f"ml_scam:{ml_scam:.2f}")
        all_patterns.extend(red_flags)

        # Ensure scam_types populated
        if is_scam and not scam_types:
            scam_types = self._infer_scam_types(clean_msg, kw_matched)

        result = ScamDetectionResult(
            is_scam=is_scam,
            confidence=round(final_confidence, 3),
            risk_score=int(final_confidence * 100),
            detected_patterns=all_patterns,
            scam_types=scam_types or (["generic_scam"] if is_scam else []),
        )

        logger.info(
            f"Detection: is_scam={is_scam}, confidence={final_confidence:.3f}, "
            f"kw={kw_score:.2f}, pat={pat_score:.2f}, ctx={ctx_score:.2f}, "
            f"feat={feat_score:.2f}, ml={ml_scam:.2f}, types={scam_types}"
        )

        return result

    def _analyze_short_message(self, message: str) -> ScamDetectionResult:
        """Lighter analysis for very short messages."""
        msg_lower = message.lower()

        # Quick keyword check
        high_risk_short = {"otp", "send money", "blocked", "suspended", "urgent",
                           "click", "verify", "upi", "pin", "cvv"}
        matched = [kw for kw in high_risk_short if kw in msg_lower]

        if matched:
            return ScamDetectionResult(
                is_scam=True,
                confidence=0.6,
                risk_score=60,
                detected_patterns=[f"short_msg_keyword:{','.join(matched)}"],
                scam_types=["generic_scam"],
            )

        return ScamDetectionResult(
            is_scam=False, confidence=0.1, risk_score=10,
            detected_patterns=["short_message"], scam_types=[],
        )

    def _get_ml_probs(self, message: str) -> Dict[str, float]:
        if ML_AVAILABLE:
            return get_ml_prediction(message)
        return self._fallback_probs(message)

    def _fallback_probs(self, message: str) -> Dict[str, float]:
        msg_lower = message.lower()
        scam_kws = [
            "send otp", "share otp", "blocked", "suspended", "frozen",
            "pay now", "transfer money", "click here", "verify now",
            "give cvv", "share pin", "lottery", "won prize", "claim now",
        ]
        sus_kws = [
            "verify", "urgent", "immediately", "action required",
            "security alert", "unusual activity", "kyc update",
        ]
        sc = sum(1 for kw in scam_kws if kw in msg_lower)
        su = sum(1 for kw in sus_kws if kw in msg_lower)

        if sc >= 2:
            return {"legit": 0.1, "suspicious": 0.15, "scam": 0.75}
        elif sc == 1:
            return {"legit": 0.2, "suspicious": 0.3, "scam": 0.5}
        elif su >= 2:
            return {"legit": 0.25, "suspicious": 0.6, "scam": 0.15}
        elif su == 1:
            return {"legit": 0.4, "suspicious": 0.45, "scam": 0.15}
        return {"legit": 0.7, "suspicious": 0.2, "scam": 0.1}

    def _infer_scam_types(self, message: str, keywords: List[str]) -> List[str]:
        """Infer scam types from detected keywords when patterns didn't match."""
        msg_lower = message.lower()
        types = set()

        keyword_type_map = {
            "bank_impersonation": ["bank", "account", "sbi", "hdfc", "icici", "rbi"],
            "upi_fraud": ["upi", "paytm", "phonepe", "gpay", "send money", "transfer"],
            "otp_theft": ["otp", "pin", "cvv", "password", "verification code", "mpin"],
            "phishing_link": ["click", "link", "visit", "website"],
            "investment_scam": ["invest", "returns", "profit", "double money", "scheme"],
            "job_scam": ["work from home", "part time", "earn", "registration fee"],
            "prize_lottery": ["won", "lottery", "prize", "reward", "winner", "claim"],
            "tax_legal": ["income tax", "legal action", "court", "arrested", "fir"],
            "kyc_update": ["kyc"],
            "refund_scam": ["refund", "cashback"],
            "electricity_bill": ["electricity", "power", "bill", "disconnect", "overdue"],
            "govt_scheme": ["government", "scheme", "subsidy", "yojana", "benefit", "aadhaar"],
            "crypto_investment": ["crypto", "bitcoin", "ethereum", "mining", "staking", "nft"],
            "customs_parcel": ["customs", "parcel", "package", "courier", "shipment", "seized"],
            "insurance": ["insurance", "policy", "premium", "claim", "matured", "lapsed"],
            "loan_approval": ["loan", "pre-approved", "sanctioned", "emi", "credit"],
            "tech_support": ["virus", "malware", "hacked", "compromised", "antivirus"],
        }

        for stype, kws in keyword_type_map.items():
            if any(kw in msg_lower for kw in kws):
                types.add(stype)

        return list(types)

    def should_activate_agent(
        self,
        detection_result: ScamDetectionResult,
        session_id: str = None,
        extracted_intel: Dict = None,
    ) -> bool:
        """
        Determine if AI agent should be activated.
        For a honeypot, we want the agent active for virtually all messages
        to maximize engagement and intelligence extraction.
        """
        # Always activate if any scam detected
        if detection_result.is_scam:
            return True

        # Activate if any suspicious turn
        if session_id:
            if self.suspicious_count.get(session_id, 0) >= 1:
                return True

        # Activate if any intel detected
        if extracted_intel:
            if any(extracted_intel.get(k) for k in
                   ["upiIds", "phishingLinks", "phoneNumbers", "emailAddresses",
                    "bankAccounts", "caseIds", "policyNumbers", "orderNumbers"]):
                return True

        # Activate even for moderate confidence — honeypot should always engage
        if detection_result.confidence > 0.25:
            return True

        return False

    def reset_session(self, session_id: str):
        self.suspicious_count.pop(session_id, None)


# Singleton
hybrid_detector = HybridScamDetector()


def detect_scam(
    message: str,
    conversation_history: List[Dict] = None,
    session_id: str = None,
) -> ScamDetectionResult:
    """Main detection function."""
    return hybrid_detector.analyze(message, session_id, conversation_history)


def should_activate_agent(
    detection_result: ScamDetectionResult,
    session_id: str = None,
    extracted_intel: Dict = None,
) -> bool:
    """Check if agent should be activated."""
    return hybrid_detector.should_activate_agent(detection_result, session_id, extracted_intel)


def is_message_scam(message: str) -> bool:
    """Quick scam check."""
    return detect_scam(message).is_scam
