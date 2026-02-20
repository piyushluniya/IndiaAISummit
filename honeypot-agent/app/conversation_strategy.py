"""
Adaptive Conversation Strategy Module for the Honeypot System.
Manages conversation tactics, stage detection, and goal setting.
"""

import random
from typing import Dict, List, Optional


# Persona definitions
PERSONAS = {
    "elderly": {
        "name": "Kamla Devi",
        "age_range": "60-70",
        "tech_level": "very low",
        "traits": "confused, polite, trusting, not tech-savvy, religious",
        "style": "formal, uses sir/madam, asks basic questions, mentions family",
        "emotion_map": {
            "early": "worried and confused",
            "middle": "anxious but cooperative",
            "late": "increasingly doubtful, mentions asking family",
        },
    },
    "professional": {
        "name": "Rahul Sharma",
        "age_range": "28-40",
        "tech_level": "moderate",
        "traits": "busy, cautious, somewhat tech-aware, professional",
        "style": "professional, asks for verification, time-constrained",
        "emotion_map": {
            "early": "slightly concerned but busy",
            "middle": "cautious and demanding proof",
            "late": "suspicious and questioning legitimacy",
        },
    },
    "student": {
        "name": "Priya Patel",
        "age_range": "19-24",
        "tech_level": "moderate-high",
        "traits": "curious, casual, somewhat savvy but inexperienced with banking",
        "style": "informal, casual English, asks friends/family",
        "emotion_map": {
            "early": "confused and slightly worried",
            "middle": "curious but hesitant",
            "late": "suspicious, mentions telling parents",
        },
    },
    "homemaker": {
        "name": "Sunita Verma",
        "age_range": "35-50",
        "tech_level": "low",
        "traits": "worried, family-focused, relies on spouse, careful with money",
        "style": "concerned, mentions family, seeks reassurance",
        "emotion_map": {
            "early": "very worried about family finances",
            "middle": "hesitant, wants to consult husband",
            "late": "growing doubt, wants to visit bank in person",
        },
    },
    "business_owner": {
        "name": "Ajay Gupta",
        "age_range": "40-55",
        "tech_level": "moderate",
        "traits": "practical, transaction-focused, time-sensitive, sharp",
        "style": "direct, asks about business impact, wants specifics",
        "emotion_map": {
            "early": "concerned about business disruption",
            "middle": "demanding details and verification",
            "late": "pointing out inconsistencies, threatening to call bank",
        },
    },
}

# Stage strategies
STAGE_STRATEGIES = {
    "early": {
        "goal": "appear_vulnerable",
        "tactics": ["ask_basic_questions", "show_concern", "be_polite", "seem_naive"],
        "target_info": ["caller_identity", "reason_for_call", "organization"],
        "response_style": "worried_but_compliant",
        "questions": [
            "What happened to my account?",
            "Who is calling? Which bank?",
            "Why are you contacting me?",
            "Is this very serious?",
            "What should I do?",
        ],
    },
    "middle": {
        "goal": "extract_contact_info",
        "tactics": ["ask_verification", "show_hesitation", "request_details", "stall"],
        "target_info": ["employee_id", "phone_number", "upi_id", "official_link"],
        "response_style": "cautious_but_engaged",
        "questions": [
            "Can you give me your employee ID?",
            "What is the official number I can call back?",
            "Where exactly should I send the payment?",
            "Can you send me an official email about this?",
            "What is your UPI ID for verification?",
        ],
    },
    "late": {
        "goal": "maximize_extraction_show_suspicion",
        "tactics": ["point_out_inconsistencies", "ask_hard_questions", "demand_proof"],
        "target_info": ["remaining_intel", "contradictions"],
        "response_style": "increasingly_suspicious",
        "questions": [
            "Why didn't the bank send me an SMS about this?",
            "I want to call the bank directly to verify.",
            "This seems unusual. Banks don't usually call like this.",
            "Can I visit the branch instead?",
            "Let me check with my family first.",
        ],
    },
}

# Stalling responses
STALLING_RESPONSES = [
    "Let me check with my family first, please hold.",
    "I need to find my documents. Can you wait a moment?",
    "Can you call back in 10 minutes? I am in the middle of something.",
    "I am having trouble understanding. Can you explain again slowly?",
    "Wait, let me get my reading glasses to see the message properly.",
    "My phone battery is low. Can you give me a number to call back?",
    "Let me write this down. Can you repeat that slowly?",
    "I need to go to the other room to find my bank passbook.",
]


def get_stage(turn_number: int, max_turns: int = 20) -> str:
    """Determine conversation stage based on turn number."""
    if turn_number <= max_turns * 0.25:
        return "early"
    elif turn_number <= max_turns * 0.6:
        return "middle"
    else:
        return "late"


def select_persona(session_id: str) -> Dict:
    """
    Select a persona for a session. Uses session_id hash for consistency.

    Args:
        session_id: Session identifier

    Returns:
        Persona definition dict
    """
    persona_keys = list(PERSONAS.keys())
    idx = hash(session_id) % len(persona_keys)
    key = persona_keys[idx]
    persona = PERSONAS[key].copy()
    persona["type"] = key
    return persona


def get_strategy(
    session_id: str,
    turn_number: int,
    detected_scam_types: List[str] = None,
    extracted_intel: Dict = None,
    behavior_analysis: Dict = None,
) -> Dict:
    """
    Get conversation strategy for the current turn.

    Args:
        session_id: Session identifier
        turn_number: Current turn number
        detected_scam_types: Detected scam types
        extracted_intel: Already extracted intelligence
        behavior_analysis: Behavior analysis results

    Returns:
        Strategy dict for this turn
    """
    stage = get_stage(turn_number)
    persona = select_persona(session_id)
    strategy = STAGE_STRATEGIES[stage].copy()

    # Determine what info is still missing
    missing_info = _get_missing_info(extracted_intel or {})

    # Pick target questions based on missing info
    target_questions = []
    if "phone_number" in missing_info:
        target_questions.append("What number can I call you back on?")
    if "upi_id" in missing_info:
        target_questions.append("Where should I send payment? What is the UPI ID?")
    if "email" in missing_info:
        target_questions.append("Can you email me the details? What is your email address?")
    if "bank_account" in missing_info:
        target_questions.append("What bank account should I transfer to?")
    if "employee_id" in missing_info:
        target_questions.append("What is your employee ID?")
    if "link" in missing_info:
        target_questions.append("Can you send me the official link?")
    if "case_id" in missing_info:
        target_questions.append("What is the case number or reference ID?")
    if "policy_number" in missing_info:
        target_questions.append("What is my policy number?")
    if "order_number" in missing_info:
        target_questions.append("What is the order or transaction number?")

    emotion = persona["emotion_map"].get(stage, "neutral")

    return {
        "stage": stage,
        "persona": persona,
        "goal": strategy["goal"],
        "tactics": strategy["tactics"],
        "target_questions": target_questions or strategy["questions"],
        "response_style": strategy["response_style"],
        "emotion": emotion,
        "missing_info": missing_info,
        "turn_number": turn_number,
    }


def get_stalling_response() -> str:
    """Get a random stalling response."""
    return random.choice(STALLING_RESPONSES)


def _get_missing_info(extracted_intel: Dict) -> List[str]:
    """Determine what intelligence is still missing."""
    missing = []
    if not extracted_intel.get("phoneNumbers"):
        missing.append("phone_number")
    if not extracted_intel.get("upiIds"):
        missing.append("upi_id")
    if not extracted_intel.get("phishingLinks"):
        missing.append("link")
    if not extracted_intel.get("emailAddresses"):
        missing.append("email")
    if not extracted_intel.get("bankAccounts"):
        missing.append("bank_account")
    if not extracted_intel.get("caseIds"):
        missing.append("case_id")
    if not extracted_intel.get("policyNumbers"):
        missing.append("policy_number")
    if not extracted_intel.get("orderNumbers"):
        missing.append("order_number")
    # Always try to get employee ID
    missing.append("employee_id")
    return missing
