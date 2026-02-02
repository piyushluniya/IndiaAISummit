"""
Scam Detection Module for the Honeypot System.
Implements multi-factor scam detection using keywords, patterns, and heuristics.
"""

import re
from typing import List, Tuple, Dict, Set
from .models import ScamDetectionResult
from .config import (
    logger,
    settings,
    HIGH_RISK_KEYWORDS,
    MEDIUM_RISK_KEYWORDS,
    SCAM_PATTERNS,
    URGENCY_INDICATORS,
    THREAT_INDICATORS
)


class ScamDetector:
    """
    Multi-factor scam detection engine.
    Uses keyword scoring, pattern matching, and contextual analysis.
    """

    # Scoring weights
    HIGH_RISK_SCORE = 10
    MEDIUM_RISK_SCORE = 5
    PATTERN_MATCH_SCORE = 15
    URGENCY_SCORE = 10
    THREAT_SCORE = 10
    MULTIPLE_PATTERN_BONUS = 10

    def __init__(self):
        """Initialize the scam detector with pre-compiled patterns."""
        self.high_risk_keywords = set(k.lower() for k in HIGH_RISK_KEYWORDS)
        self.medium_risk_keywords = set(k.lower() for k in MEDIUM_RISK_KEYWORDS)
        self.urgency_indicators = set(u.lower() for u in URGENCY_INDICATORS)
        self.threat_indicators = set(t.lower() for t in THREAT_INDICATORS)

        # Pre-compile regex patterns for efficiency
        self.compiled_patterns = self._compile_patterns()

        logger.info("ScamDetector initialized with keyword and pattern matching")

    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile regex patterns for each scam type."""
        compiled = {}
        for scam_type, patterns in SCAM_PATTERNS.items():
            compiled[scam_type] = [
                re.compile(re.escape(p), re.IGNORECASE)
                for p in patterns
            ]
        return compiled

    def analyze(self, message: str, conversation_history: List[Dict] = None) -> ScamDetectionResult:
        """
        Analyze a message for scam indicators.

        Args:
            message: The message text to analyze
            conversation_history: Optional list of previous messages for context

        Returns:
            ScamDetectionResult with detection details
        """
        message_lower = message.lower()

        # Calculate keyword score
        keyword_score, matched_high, matched_medium = self._calculate_keyword_score(message_lower)

        # Detect scam patterns
        detected_patterns, scam_types = self._detect_patterns(message_lower)

        # Check for urgency indicators
        urgency_found = self._check_urgency(message_lower)
        if urgency_found:
            keyword_score += self.URGENCY_SCORE
            detected_patterns.append("urgency_tactic")

        # Check for threat indicators
        threat_found = self._check_threats(message_lower)
        if threat_found:
            keyword_score += self.THREAT_SCORE
            detected_patterns.append("threat_tactic")

        # Add pattern match scores
        pattern_score = len(scam_types) * self.PATTERN_MATCH_SCORE
        if len(scam_types) > 1:
            pattern_score += self.MULTIPLE_PATTERN_BONUS

        # Calculate total risk score
        total_score = keyword_score + pattern_score

        # Analyze conversation context if available
        if conversation_history:
            context_score = self._analyze_context(conversation_history)
            total_score += context_score

        # Determine if it's a scam and confidence level
        is_scam, confidence = self._calculate_verdict(
            total_score,
            len(scam_types),
            matched_high,
            matched_medium
        )

        result = ScamDetectionResult(
            is_scam=is_scam,
            confidence=confidence,
            risk_score=total_score,
            detected_patterns=list(set(detected_patterns)),
            scam_types=scam_types
        )

        logger.info(
            f"Scam analysis complete: is_scam={is_scam}, "
            f"confidence={confidence:.2f}, score={total_score}"
        )

        return result

    def _calculate_keyword_score(self, message: str) -> Tuple[int, Set[str], Set[str]]:
        """
        Calculate score based on keyword presence.

        Returns:
            Tuple of (score, matched_high_risk, matched_medium_risk)
        """
        score = 0
        matched_high = set()
        matched_medium = set()

        # Check high-risk keywords
        for keyword in self.high_risk_keywords:
            if keyword in message:
                score += self.HIGH_RISK_SCORE
                matched_high.add(keyword)

        # Check medium-risk keywords
        for keyword in self.medium_risk_keywords:
            if keyword in message:
                score += self.MEDIUM_RISK_SCORE
                matched_medium.add(keyword)

        return score, matched_high, matched_medium

    def _detect_patterns(self, message: str) -> Tuple[List[str], List[str]]:
        """
        Detect scam patterns in the message.

        Returns:
            Tuple of (detected_patterns, scam_types)
        """
        detected_patterns = []
        scam_types = []

        for scam_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(message):
                    detected_patterns.append(pattern.pattern)
                    if scam_type not in scam_types:
                        scam_types.append(scam_type)
                    break  # Found match for this type, move to next

        return detected_patterns, scam_types

    def _check_urgency(self, message: str) -> bool:
        """Check for urgency indicators in the message."""
        for indicator in self.urgency_indicators:
            if indicator in message:
                return True
        return False

    def _check_threats(self, message: str) -> bool:
        """Check for threat indicators in the message."""
        for indicator in self.threat_indicators:
            if indicator in message:
                return True
        return False

    def _analyze_context(self, history: List[Dict]) -> int:
        """
        Analyze conversation context for escalating scam patterns.

        Returns:
            Additional score based on context analysis
        """
        context_score = 0

        if not history:
            return context_score

        # Check for escalating urgency
        urgency_count = 0
        request_for_info_count = 0

        for msg in history:
            if msg.get("sender", "").lower() in ["scammer", "unknown"]:
                text = msg.get("text", "").lower()

                # Count urgency mentions
                for indicator in self.urgency_indicators:
                    if indicator in text:
                        urgency_count += 1
                        break

                # Count requests for personal information
                info_keywords = ["send", "share", "give", "tell", "provide"]
                for keyword in info_keywords:
                    if keyword in text:
                        request_for_info_count += 1
                        break

        # Add score for repeated urgency
        if urgency_count >= 2:
            context_score += 10

        # Add score for multiple information requests
        if request_for_info_count >= 2:
            context_score += 15

        return context_score

    def _calculate_verdict(
        self,
        total_score: int,
        pattern_count: int,
        matched_high: Set[str],
        matched_medium: Set[str]
    ) -> Tuple[bool, float]:
        """
        Calculate final verdict and confidence score.

        Returns:
            Tuple of (is_scam, confidence)
        """
        threshold = settings.SCAM_KEYWORD_THRESHOLD

        # Calculate base confidence from score
        if total_score >= threshold * 3:
            confidence = 0.98
        elif total_score >= threshold * 2:
            confidence = 0.95
        elif total_score >= threshold * 1.5:
            confidence = 0.90
        elif total_score >= threshold:
            confidence = 0.85
        elif total_score >= threshold * 0.7:
            confidence = 0.70
        else:
            confidence = max(0.1, total_score / 100)

        # Boost confidence for multiple high-risk matches
        if len(matched_high) >= 3:
            confidence = min(0.99, confidence + 0.05)

        # Boost for multiple pattern types
        if pattern_count >= 2:
            confidence = min(0.99, confidence + 0.05)

        # Determine if it's a scam
        is_scam = total_score >= threshold or pattern_count >= 2 or len(matched_high) >= 2

        return is_scam, confidence

    def get_detected_keywords(self, message: str) -> List[str]:
        """
        Get list of all detected suspicious keywords in a message.

        Args:
            message: Message text to analyze

        Returns:
            List of detected keywords
        """
        message_lower = message.lower()
        detected = []

        for keyword in self.high_risk_keywords:
            if keyword in message_lower:
                detected.append(keyword)

        for keyword in self.medium_risk_keywords:
            if keyword in message_lower:
                detected.append(keyword)

        return detected

    def get_scam_type_description(self, scam_types: List[str]) -> str:
        """
        Get human-readable description of detected scam types.

        Args:
            scam_types: List of detected scam type identifiers

        Returns:
            Formatted description string
        """
        descriptions = {
            "bank_fraud": "Bank account/card fraud attempt",
            "upi_fraud": "UPI payment fraud",
            "otp_scam": "OTP/verification code theft",
            "phishing": "Phishing/link-based scam",
            "impersonation": "Authority impersonation",
            "lottery_scam": "Lottery/prize scam",
            "job_scam": "Job/investment fraud"
        }

        if not scam_types:
            return "Generic scam attempt"

        return ", ".join(
            descriptions.get(st, st.replace("_", " ").title())
            for st in scam_types
        )


# Singleton instance
scam_detector = ScamDetector()


def detect_scam(message: str, conversation_history: List[Dict] = None) -> ScamDetectionResult:
    """
    Convenience function to detect scams using the singleton detector.

    Args:
        message: Message text to analyze
        conversation_history: Optional conversation history

    Returns:
        ScamDetectionResult with detection details
    """
    return scam_detector.analyze(message, conversation_history)


def is_message_scam(message: str) -> bool:
    """
    Quick check if a message is a scam.

    Args:
        message: Message text to check

    Returns:
        True if message is detected as scam
    """
    result = scam_detector.analyze(message)
    return result.is_scam
