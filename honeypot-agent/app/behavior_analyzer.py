"""
Conversation Behavior Analysis Module for the Honeypot System.
Tracks scammer behavior patterns, escalation, and manipulation tactics.
"""

from typing import Dict, List, Optional
from .urgency_detector import detect_urgency, detect_threats


class BehaviorAnalyzer:
    """Analyzes scammer behavior across a conversation."""

    # Info request patterns
    INFO_REQUEST_PATTERNS = {
        "otp": ["otp", "one time password", "verification code", "code", "pin"],
        "upi_id": ["upi", "upi id", "paytm", "phonepe", "gpay", "google pay", "send money"],
        "account_number": ["account number", "account no", "a/c number", "bank account"],
        "card_details": ["card number", "cvv", "expiry", "credit card", "debit card"],
        "personal_info": ["aadhaar", "aadhar", "pan card", "pan number", "date of birth", "dob", "address"],
        "phone_number": ["phone number", "mobile number", "contact number", "whatsapp"],
        "password": ["password", "passcode", "login", "credentials"],
    }

    # Trust-building tactics
    TRUST_TACTICS = {
        "claims_bank_employee": [
            "bank manager", "bank officer", "bank employee", "calling from bank",
            "from the bank", "bank representative", "branch manager",
        ],
        "claims_government": [
            "government", "income tax", "rbi", "reserve bank", "cyber cell",
            "police", "court order", "official",
        ],
        "uses_official_language": [
            "as per rbi guidelines", "regulatory", "compliance", "mandatory",
            "according to policy", "directive", "notification",
        ],
        "fake_credentials": [
            "employee id", "badge number", "officer id", "reference number",
            "case number", "complaint number",
        ],
        "emotional_manipulation": [
            "for your safety", "to protect you", "help you", "concerned",
            "worried about your account", "in your interest",
        ],
    }

    def __init__(self):
        self._session_data: Dict[str, Dict] = {}

    def analyze_conversation(
        self,
        session_id: str,
        conversation_history: List[Dict],
    ) -> Dict:
        """
        Analyze full conversation behavior.

        Args:
            session_id: Session identifier
            conversation_history: List of message dicts

        Returns:
            Behavior analysis result dict
        """
        scammer_messages = [
            m for m in conversation_history
            if m.get("sender", "").lower() in ("scammer", "unknown")
        ]

        if not scammer_messages:
            return self._empty_result()

        # Escalation analysis
        escalation = self._analyze_escalation(scammer_messages)

        # Info request tracking
        info_requests = self._track_info_requests(scammer_messages)

        # Trust tactic detection
        trust_tactics = self._detect_trust_tactics(scammer_messages)

        # Conversation metrics
        metrics = self._compute_metrics(scammer_messages, conversation_history)

        result = {
            "escalation_detected": escalation["detected"],
            "escalation_pattern": escalation["pattern"],
            "escalation_scores": escalation["scores"],
            "info_requests": info_requests,
            "trust_tactics": trust_tactics,
            "conversation_metrics": metrics,
        }

        # Cache for strategy module
        self._session_data[session_id] = result
        return result

    def get_cached(self, session_id: str) -> Optional[Dict]:
        return self._session_data.get(session_id)

    def _analyze_escalation(self, scammer_messages: List[Dict]) -> Dict:
        """Track pressure escalation over messages."""
        if len(scammer_messages) < 2:
            return {"detected": False, "pattern": "none", "scores": []}

        scores = []
        for msg in scammer_messages:
            text = msg.get("text", "")
            urgency = detect_urgency(text)
            threats = detect_threats(text)
            combined = (urgency["urgency_score"] + threats["threat_score"]) / 2
            scores.append(round(combined, 3))

        # Detect pattern
        if len(scores) >= 3:
            # Check if last third has higher avg than first third
            third = max(1, len(scores) // 3)
            early_avg = sum(scores[:third]) / third
            late_avg = sum(scores[-third:]) / third

            if late_avg > early_avg + 0.15:
                pattern = "gradual"
                detected = True
            elif len(scores) >= 2 and scores[-1] > scores[-2] + 0.3:
                pattern = "sudden"
                detected = True
            else:
                pattern = "none"
                detected = late_avg > 0.3
        else:
            pattern = "none"
            detected = any(s > 0.5 for s in scores)

        return {"detected": detected, "pattern": pattern, "scores": scores}

    def _track_info_requests(self, scammer_messages: List[Dict]) -> Dict[str, int]:
        """Count what info the scammer is asking for."""
        counts: Dict[str, int] = {}

        for msg in scammer_messages:
            text = msg.get("text", "").lower()
            for info_type, keywords in self.INFO_REQUEST_PATTERNS.items():
                for kw in keywords:
                    if kw in text:
                        counts[info_type] = counts.get(info_type, 0) + 1
                        break  # Count once per message per type

        return counts

    def _detect_trust_tactics(self, scammer_messages: List[Dict]) -> List[str]:
        """Detect trust-building manipulation tactics."""
        tactics_found = set()

        for msg in scammer_messages:
            text = msg.get("text", "").lower()
            for tactic, keywords in self.TRUST_TACTICS.items():
                for kw in keywords:
                    if kw in text:
                        tactics_found.add(tactic)
                        break

        return list(tactics_found)

    def _compute_metrics(
        self, scammer_messages: List[Dict], all_messages: List[Dict]
    ) -> Dict:
        """Compute conversation metrics."""
        scammer_lengths = [len(m.get("text", "")) for m in scammer_messages]
        avg_len = sum(scammer_lengths) / max(1, len(scammer_lengths))

        # Topic changes: count when scammer shifts from one type to another
        topics_per_msg = []
        for msg in scammer_messages:
            text = msg.get("text", "").lower()
            topics = set()
            for info_type, keywords in self.INFO_REQUEST_PATTERNS.items():
                for kw in keywords:
                    if kw in text:
                        topics.add(info_type)
                        break
            topics_per_msg.append(topics)

        topic_changes = 0
        for i in range(1, len(topics_per_msg)):
            if topics_per_msg[i] and topics_per_msg[i] != topics_per_msg[i - 1]:
                topic_changes += 1

        # Pressure increase
        urgency_scores = []
        for msg in scammer_messages:
            u = detect_urgency(msg.get("text", ""))
            urgency_scores.append(u["urgency_score"])

        if len(urgency_scores) >= 2:
            pressure_increase = round(urgency_scores[-1] - urgency_scores[0], 3)
        else:
            pressure_increase = 0.0

        return {
            "avg_message_length": round(avg_len, 1),
            "topic_changes": topic_changes,
            "pressure_increase": pressure_increase,
            "total_scammer_messages": len(scammer_messages),
        }

    def _empty_result(self) -> Dict:
        return {
            "escalation_detected": False,
            "escalation_pattern": "none",
            "escalation_scores": [],
            "info_requests": {},
            "trust_tactics": [],
            "conversation_metrics": {
                "avg_message_length": 0,
                "topic_changes": 0,
                "pressure_increase": 0.0,
                "total_scammer_messages": 0,
            },
        }


# Singleton
behavior_analyzer = BehaviorAnalyzer()
