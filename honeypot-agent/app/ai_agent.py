"""
Enhanced AI Agent Module for the Honeypot System.
Integrates with Google Gemini API to generate human-like victim responses
using multiple personas, conversation stages, and adaptive strategies.
"""

import random
import time
import hashlib
from typing import List, Dict, Optional
from functools import lru_cache

import google.generativeai as genai
from .config import logger, settings, FALLBACK_RESPONSES
from .conversation_strategy import (
    get_strategy, select_persona, get_stage, get_stalling_response,
    PERSONAS, STAGE_STRATEGIES,
)


class VictimAgent:
    """
    AI-powered agent that simulates a potential scam victim.
    Uses multiple personas, conversation stages, and Gemini AI.
    """

    def __init__(self):
        self.model = None
        self.initialized = False
        self._used_fallbacks: Dict[str, set] = {}  # session_id -> set of used indices
        self._initialize_client()

    def _initialize_client(self):
        try:
            if not settings.GEMINI_API_KEY:
                logger.warning("GEMINI_API_KEY not set, using fallback responses")
                return

            genai.configure(api_key=settings.GEMINI_API_KEY)

            safety_settings = [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_ONLY_HIGH"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_ONLY_HIGH"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_ONLY_HIGH"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_ONLY_HIGH"},
            ]

            self.model = genai.GenerativeModel(
                model_name=settings.GEMINI_MODEL,
                safety_settings=safety_settings,
            )
            self.initialized = True
            logger.info(f"Gemini AI agent initialized: {settings.GEMINI_MODEL}")

        except Exception as e:
            logger.error(f"Failed to initialize Gemini: {e}")
            self.initialized = False

    # ── Main response generation ──

    def generate_victim_response(
        self,
        scammer_message: str,
        conversation_history: List[Dict] = None,
        detected_scam_types: List[str] = None,
        session_id: str = None,
    ) -> str:
        """Generate a victim response using persona + stage strategy."""

        if not scammer_message or not scammer_message.strip():
            return "Hello? Is someone there?"

        # Determine turn number from history
        turn_number = 1
        if conversation_history:
            scammer_turns = sum(
                1 for m in conversation_history
                if m.get("sender", "").lower() in ("scammer", "unknown")
            )
            turn_number = scammer_turns + 1

        # Get strategy
        sid = session_id or "default"
        strategy = get_strategy(
            sid, turn_number, detected_scam_types or [],
        )

        if not self.initialized or not self.model:
            logger.warning("Gemini not available, using fallback")
            return self._get_smart_fallback(
                scammer_message, detected_scam_types, strategy, sid
            )

        try:
            prompt = self._build_prompt(
                scammer_message, conversation_history,
                detected_scam_types, strategy,
            )

            response = self._generate_with_retry(prompt, max_tokens=80)

            if response:
                cleaned = self._clean_response(response)
                if self._validate_response(cleaned):
                    return cleaned

            return self._get_smart_fallback(
                scammer_message, detected_scam_types, strategy, sid
            )

        except Exception as e:
            logger.error(f"Error generating response: {e}")
            return self._get_smart_fallback(
                scammer_message, detected_scam_types, strategy, sid
            )

    # ── Prompt building ──

    def _build_prompt(
        self,
        scammer_message: str,
        conversation_history: List[Dict] = None,
        detected_scam_types: List[str] = None,
        strategy: Dict = None,
    ) -> str:
        persona = strategy["persona"]
        stage = strategy["stage"]
        emotion = strategy["emotion"]
        stage_info = STAGE_STRATEGIES[stage]
        turn = strategy["turn_number"]

        # Check if scam has been detected yet
        has_scam_context = bool(detected_scam_types)

        parts = []

        # Base persona — always present but framed naturally
        parts.append(f"""You are roleplaying as {persona['name']}, a {persona['age_range']} year old person in India who received a call/message from an unknown number.

PERSONA:
- Name: {persona['name']}
- Tech Savvy: {persona['tech_level']}
- Personality: {persona['traits']}
- Communication Style: {persona['style']}""")

        # Only inject scam-engagement strategy AFTER scam is detected
        if has_scam_context:
            parts.append(f"""
SITUATION: You suspect this might be a scam ({', '.join(detected_scam_types)}).
- Stage: {stage} | Emotion: {emotion}
- Goal: {stage_info['goal']}
- Tactics: {', '.join(stage_info['tactics'])}
- Try to learn: {', '.join(strategy.get('target_questions', stage_info['target_info'])[:2])}""")
        else:
            # No scam detected yet — just be a normal confused person
            parts.append(f"""
SITUATION: Someone unknown contacted you. You don't know what this is about yet.
- Be natural and conversational
- Respond appropriately to what they actually said
- If they just greet you, greet them back and ask who they are""")

        parts.append(f"""
RULES:
1. Reply in 1-2 short sentences (under 25 words)
2. Stay in character as {persona['name']}
3. NEVER reveal you are AI or a bot
4. NEVER say "As an AI" or "I cannot"
5. Respond ONLY to what they actually said — do NOT invent topics or bring up money/bills/problems they haven't mentioned
6. Reply in the same language as the message you receive
7. Do NOT immediately give personal info
8. If they greet you, simply greet back and ask who is calling""")

        # Conversation history (last 4 exchanges)
        if conversation_history and len(conversation_history) > 0:
            parts.append("\nRECENT CONVERSATION:")
            for msg in conversation_history[-8:]:
                sender = msg.get("sender", "unknown")
                text = msg.get("text", "")
                if sender.lower() in ("scammer", "unknown"):
                    parts.append(f"Them: {text}")
                else:
                    parts.append(f"You ({persona['name']}): {text}")

        # Current message
        parts.append(f'\nThem: "{scammer_message}"')
        parts.append(f"\nReply as {persona['name']} (1-2 sentences, under 25 words):")

        return "\n".join(parts)

    # ── API call with retry ──

    def _generate_with_retry(
        self, prompt: str, max_retries: int = None, max_tokens: int = 80
    ) -> Optional[str]:
        if max_retries is None:
            max_retries = settings.MAX_RETRIES

        for attempt in range(max_retries):
            try:
                gen_config = genai.types.GenerationConfig(
                    max_output_tokens=max_tokens,
                    temperature=0.8,
                    top_p=0.9,
                    top_k=40,
                )

                response = self.model.generate_content(
                    prompt, generation_config=gen_config,
                )

                if response and response.text:
                    text = response.text.strip()
                    logger.info(f"Gemini raw ({len(text)} chars): {text[:100]}...")
                    return text

            except Exception as e:
                logger.warning(f"Gemini attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(settings.RETRY_DELAY_SECONDS * (2 ** attempt))

        return None

    # ── Response cleaning & validation ──

    def _clean_response(self, response: str) -> str:
        cleaned = response.strip()

        # Remove role prefixes
        for prefix in ["Victim:", "Me:", "Response:", "Reply:", "Priya:",
                       "Kamla:", "Rahul:", "Sunita:", "Ajay:",
                       "As the victim:", "Speaking as the victim:",
                       "Kamla Devi:", "Rahul Sharma:", "Priya Patel:",
                       "Sunita Verma:", "Ajay Gupta:"]:
            if cleaned.lower().startswith(prefix.lower()):
                cleaned = cleaned[len(prefix):].strip()

        # Remove wrapping quotes
        if cleaned.startswith('"') and cleaned.endswith('"'):
            cleaned = cleaned[1:-1]
        if cleaned.startswith("'") and cleaned.endswith("'"):
            cleaned = cleaned[1:-1]

        # Truncate overly long responses
        if len(cleaned) > 200:
            sentences = cleaned.split(". ")
            if len(sentences) > 2:
                cleaned = ". ".join(sentences[:2]) + "."

        # Ensure ends with punctuation
        if cleaned and cleaned[-1] not in ".?!":
            cleaned += "?"

        return cleaned

    def _validate_response(self, response: str) -> bool:
        if not response or len(response) < 5:
            return False
        if len(response) > 300:
            return False

        lower = response.lower()
        bad_phrases = [
            "as an ai", "i'm an ai", "i am an ai", "artificial intelligence",
            "language model", "i cannot assist", "i'm unable", "i am unable",
            "i'm a bot", "i am a bot", "as a chatbot",
        ]
        return not any(bp in lower for bp in bad_phrases)

    # ── Smart fallback system ──

    def _get_smart_fallback(
        self,
        scammer_message: str,
        detected_scam_types: List[str] = None,
        strategy: Dict = None,
        session_id: str = "default",
    ) -> str:
        """Context-aware fallback with no repeats per session."""
        stage = strategy["stage"] if strategy else "early"
        scam_type = (detected_scam_types or ["generic"])[0] if detected_scam_types else "generic"
        msg_lower = scammer_message.lower()

        # Build candidate pool based on scam type + stage
        candidates = self._get_fallback_pool(msg_lower, scam_type, stage)

        # Filter out already used
        used = self._used_fallbacks.get(session_id, set())
        available = [(i, r) for i, r in enumerate(candidates) if i not in used]

        if not available:
            # Reset and use all
            used.clear()
            available = list(enumerate(candidates))

        idx, response = random.choice(available)
        used.add(idx)
        self._used_fallbacks[session_id] = used

        return response

    def _get_fallback_pool(self, msg_lower: str, scam_type: str, stage: str) -> List[str]:
        """Get fallback response pool based on context."""

        # ── EARLY STAGE ──
        early = {
            "bank_impersonation": [
                "Oh no! What happened to my account? Which bank are you from?",
                "My account has a problem? But I just used it. What is your name?",
                "This is worrying. Is my money safe? Who am I speaking to?",
                "What? My account? I don't understand. Can you explain?",
            ],
            "upi_fraud": [
                "UPI? I am confused. What payment are you talking about?",
                "Send money? For what? My husband handles payments.",
                "I don't understand UPI very well. Why do I need to pay?",
                "Payment? I didn't order anything. What is this about?",
            ],
            "otp_theft": [
                "OTP? What is that? I got many messages on my phone.",
                "Code? I see some numbers on my phone. What are they for?",
                "Verification code? My son usually helps me with this.",
                "I don't understand these codes. What should I do?",
            ],
            "phishing_link": [
                "Click a link? My son says I shouldn't click unknown links.",
                "Is this link safe? What will happen if I click it?",
                "I am scared of clicking links. Can you just tell me what to do?",
                "Link? What is this for? Can I go to the bank instead?",
            ],
            "investment_scam": [
                "Investment? What kind of returns are you offering?",
                "This sounds interesting. But is it safe? Who are you?",
                "How can you guarantee returns? What company is this?",
                "My husband handles investments. Can you tell me more?",
            ],
            "prize_lottery": [
                "I won something? Really? What did I win?",
                "Prize? But I don't remember entering any contest!",
                "This sounds too good. How did I get selected?",
                "Lottery? I never bought any ticket. How is this possible?",
            ],
            "job_scam": [
                "Work from home? What kind of job is this?",
                "How much can I earn? What do I need to do?",
                "This sounds nice. But why is there a registration fee?",
                "Job offer? What company are you from?",
            ],
            "tax_legal": [
                "Income tax notice? But I file my returns on time!",
                "Legal action? What did I do wrong? I am very scared.",
                "Police? Why would police be involved? This is frightening.",
                "Court case? I don't understand. What is happening?",
            ],
        }

        # ── MIDDLE STAGE ──
        middle = {
            "generic": [
                "Can you give me your employee ID for verification?",
                "What is the official number I can call back to verify?",
                "Let me check with my family first. Can you hold?",
                "I need to find my documents. What exactly do you need?",
                "How do I verify this is genuine? Can you send official proof?",
                "Wait, let me write this down. What was your name again?",
                "My husband says I should not share details on phone. Why?",
                "Can you send me an official email about this?",
            ],
        }

        # ── LATE STAGE ──
        late = {
            "generic": [
                "This seems unusual. Banks don't usually call like this.",
                "I want to visit the bank branch directly to verify.",
                "Let me call the bank's official number to confirm this.",
                "My son says this might be fraud. Can you prove it's not?",
                "Why are you asking for this over phone? This feels wrong.",
                "I will check with the bank first. What branch are you from?",
                "Something doesn't feel right. I want to verify with the bank.",
                "I think I should report this. What is your full name?",
            ],
        }

        if stage == "early":
            pool = early.get(scam_type, [])
            if not pool:
                # Try matching by keyword in message
                for key, responses in early.items():
                    if any(kw in msg_lower for kw in key.split("_")):
                        pool = responses
                        break
            if not pool:
                pool = early.get("bank_impersonation", FALLBACK_RESPONSES)
        elif stage == "middle":
            pool = middle["generic"]
        else:
            pool = late["generic"]

        return pool

    # ── Agent notes generation ──

    def generate_agent_notes(
        self,
        conversation_history: List[Dict],
        detected_scam_types: List[str],
        extracted_intelligence: Dict,
    ) -> str:
        parts = []

        if detected_scam_types:
            parts.append(f"Scam types detected: {', '.join(detected_scam_types)}.")

        intel = extracted_intelligence
        if intel.get("phoneNumbers"):
            parts.append(f"Phone numbers: {', '.join(intel['phoneNumbers'])}.")
        if intel.get("upiIds"):
            parts.append(f"UPI IDs: {', '.join(intel['upiIds'])}.")
        if intel.get("bankAccounts"):
            parts.append(f"Bank accounts: {', '.join(intel['bankAccounts'])}.")
        if intel.get("phishingLinks"):
            parts.append(f"Phishing links: {', '.join(intel['phishingLinks'])}.")

        msg_count = len(conversation_history)
        parts.append(f"Conversation: {msg_count} messages exchanged.")

        # Tactics observed
        tactics = set()
        for msg in conversation_history:
            if msg.get("sender", "").lower() in ("scammer", "unknown"):
                text = msg.get("text", "").lower()
                if any(w in text for w in ["urgent", "immediately", "now"]):
                    tactics.add("urgency")
                if any(w in text for w in ["blocked", "suspended", "frozen"]):
                    tactics.add("threat")
                if any(w in text for w in ["bank", "rbi", "government", "officer"]):
                    tactics.add("impersonation")
                if any(w in text for w in ["otp", "pin", "cvv", "password"]):
                    tactics.add("info_extraction")
        if tactics:
            parts.append(f"Tactics: {', '.join(tactics)}.")

        return " ".join(parts) if parts else "Potential scam conversation logged."


# Singleton
victim_agent = VictimAgent()


def generate_response(
    scammer_message: str,
    conversation_history: List[Dict] = None,
    detected_scam_types: List[str] = None,
    session_id: str = None,
) -> str:
    """Generate a victim response."""
    return victim_agent.generate_victim_response(
        scammer_message, conversation_history,
        detected_scam_types, session_id,
    )


def generate_notes(
    conversation_history: List[Dict],
    detected_scam_types: List[str],
    extracted_intelligence: Dict,
) -> str:
    """Generate agent notes."""
    return victim_agent.generate_agent_notes(
        conversation_history, detected_scam_types, extracted_intelligence,
    )
