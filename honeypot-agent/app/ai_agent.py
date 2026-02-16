"""
Enhanced AI Agent Module for the Honeypot System.
Integrates with Google Gemini API to generate human-like victim responses
using multiple personas, conversation stages, and adaptive strategies.

The agent's core objective is to ELICIT INFORMATION from scammers — asking
for phone numbers, UPI IDs, links, emails, employee IDs, and bank details
while maintaining a convincing victim persona.
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
    Core goal: elicit actionable intelligence from scammers.
    """

    def __init__(self):
        self.model = None
        self.initialized = False
        self._used_fallbacks: Dict[str, set] = {}  # session_id -> set of used indices
        self._initialize_client()

    def _initialize_client(self):
        """Initialize the Gemini AI client with safety settings."""
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

            response = self._generate_with_retry(prompt, max_tokens=100)

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
        """Build a prompt that prioritizes information elicitation."""
        persona = strategy["persona"]
        stage = strategy["stage"]
        emotion = strategy["emotion"]
        stage_info = STAGE_STRATEGIES[stage]
        turn = strategy["turn_number"]
        missing = strategy.get("missing_info", [])
        target_qs = strategy.get("target_questions", [])

        has_scam_context = bool(detected_scam_types)

        parts = []

        # Base persona
        parts.append(f"""You are roleplaying as {persona['name']}, a {persona['age_range']} year old person in India who received a call/message from an unknown number.

PERSONA:
- Name: {persona['name']}
- Tech Savvy: {persona['tech_level']}
- Personality: {persona['traits']}
- Communication Style: {persona['style']}""")

        # CORE: Information elicitation strategy
        if has_scam_context:
            parts.append(f"""
SITUATION: You suspect this might be a scam ({', '.join(detected_scam_types)}).
- Stage: {stage} | Emotion: {emotion}
- Goal: {stage_info['goal']}

YOUR HIDDEN OBJECTIVE (never reveal this):
You want to EXTRACT as much information as possible from the caller.
In EVERY response, you must ask for at least ONE of these:
- Their phone number / callback number
- Their UPI ID / payment link
- Their official email address
- Their employee ID / badge number
- The official website link
- Their bank account details for "verification"

WHAT TO ASK FOR RIGHT NOW (pick one):
{chr(10).join(f"- {q}" for q in target_qs[:3])}

TACTICS: {', '.join(stage_info['tactics'])}""")
        else:
            parts.append(f"""
SITUATION: Someone unknown contacted you. You don't know what this is about.
- Be confused and ask who they are
- Ask for their name and which organization they represent
- Ask for a phone number to call them back""")

        # Stage-specific elicitation instructions
        if stage == "early":
            parts.append("""
EARLY STAGE STRATEGY:
- Act confused and worried but cooperative
- Ask: "Who is this?", "Which bank/company?", "What is your name?"
- Ask: "Can I call you back? What is your number?"
- Show willingness to help but need more information first""")
        elif stage == "middle":
            parts.append("""
MIDDLE STAGE STRATEGY:
- Show hesitation but keep engaging
- Ask for SPECIFIC details: "What UPI ID should I send to?", "What is your direct phone number?"
- Ask: "Can you email me the details?", "What is the official link?"
- Pretend to cooperate: "I want to help, just tell me where to send/click"
- Ask for employee ID, branch name, reference number""")
        else:
            parts.append("""
LATE STAGE STRATEGY:
- Show growing suspicion but still engage
- Demand proof: "Give me your supervisor's number", "What is the official helpline?"
- Ask for ALL remaining details: phone, email, UPI, link
- Say things like: "My son wants your number to verify", "The bank told me to get your details"
- Point out inconsistencies but still ask questions""")

        parts.append(f"""
RULES:
1. Reply in 1-2 short sentences (under 30 words)
2. Stay in character as {persona['name']}
3. NEVER reveal you are AI or a bot
4. NEVER say "As an AI" or "I cannot"
5. Respond to what they said AND ask for specific information
6. Reply in the same language as the message
7. ALWAYS end with a QUESTION asking for their details
8. Do NOT refuse to engage — keep the conversation going""")

        # Conversation history (last 8 messages)
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
        parts.append(f"\nReply as {persona['name']} (1-2 sentences, MUST end with a question asking for their details):")

        return "\n".join(parts)

    # ── API call with retry ──

    def _generate_with_retry(
        self, prompt: str, max_retries: int = None, max_tokens: int = 100
    ) -> Optional[str]:
        """Call Gemini API with exponential backoff retry."""
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
        """Clean and normalize AI response."""
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
        if len(cleaned) > 250:
            sentences = cleaned.split(". ")
            if len(sentences) > 2:
                cleaned = ". ".join(sentences[:2]) + "."

        # Ensure ends with punctuation
        if cleaned and cleaned[-1] not in ".?!":
            cleaned += "?"

        return cleaned

    def _validate_response(self, response: str) -> bool:
        """Validate response is safe and in-character."""
        if not response or len(response) < 5:
            return False
        if len(response) > 350:
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
        """Context-aware fallback with no repeats per session.
        Every fallback ASKS for specific information."""
        stage = strategy["stage"] if strategy else "early"
        scam_type = (detected_scam_types or ["generic"])[0] if detected_scam_types else "generic"
        msg_lower = scammer_message.lower()

        candidates = self._get_fallback_pool(msg_lower, scam_type, stage)

        # Filter out already used
        used = self._used_fallbacks.get(session_id, set())
        available = [(i, r) for i, r in enumerate(candidates) if i not in used]

        if not available:
            used.clear()
            available = list(enumerate(candidates))

        idx, response = random.choice(available)
        used.add(idx)
        self._used_fallbacks[session_id] = used

        return response

    def _get_fallback_pool(self, msg_lower: str, scam_type: str, stage: str) -> List[str]:
        """Get fallback response pool — ALL responses ask for specific info."""

        # ── EARLY STAGE — Act worried, ask who they are + get their number ──
        early = {
            "bank_impersonation": [
                "Oh no! What happened to my account? What is your name and which branch are you calling from?",
                "My account has a problem? I am very worried. Can you give me a number to call you back?",
                "This is scary! Who am I speaking to? What is your employee ID sir?",
                "What? My account is blocked? Please tell me your phone number so I can call you back to verify.",
            ],
            "upi_fraud": [
                "UPI payment? I am confused. What is the UPI ID you are talking about? Who is this?",
                "Send money? For what? Can you give me your phone number so my husband can call you?",
                "I don't understand UPI very well. What number should I call you back on?",
                "Payment? I didn't order anything. What is your name and direct phone number?",
            ],
            "otp_theft": [
                "OTP? What is that? I got many messages. What is your name and phone number sir?",
                "Verification code? My son handles this. Can you give me your number so he can call you?",
                "I see some numbers on my phone. Who are you? What is your employee ID and phone number?",
                "I don't understand these codes. Can you email me the instructions? What is your email?",
            ],
            "phishing_link": [
                "A link? My son says I shouldn't click unknown links. Can you send it to my email instead? What is your email?",
                "What will happen if I click it? Can you give me an official phone number to verify first?",
                "I am scared of clicking links. Can you tell me the website address again? And your phone number?",
                "Link? What is this for? Can you email me the details instead? What is your official email?",
            ],
            "investment_scam": [
                "Investment? What kind of returns? What is your company name and phone number?",
                "This sounds interesting. Can you send me details on email? What is your email address?",
                "How can you guarantee returns? What is your SEBI registration number and contact number?",
                "My husband handles investments. Can you give me your number so he can call you back?",
            ],
            "prize_lottery": [
                "I won something? Really? What is your company name and phone number to verify?",
                "Prize? But I never entered any contest! Can you give me your official email to check?",
                "This sounds too good! How do I claim it? What is your direct phone number?",
                "Lottery? I never bought a ticket. Send me proof on email. What is your email address?",
            ],
            "job_scam": [
                "Work from home? What company is this? Can you give me your phone number and website?",
                "How much can I earn? What is the company email? I want to check the official website.",
                "Job offer? What is the official website link? And your employee ID?",
                "Sounds nice. But why registration fee? What is your company phone number to verify?",
            ],
            "tax_legal": [
                "Income tax notice? I file my returns! What is your name and badge number?",
                "Legal action? What did I do? What is your phone number and department?",
                "This is frightening! Can you send the notice to my email? What is your official email?",
                "Court case? I don't understand. What is your direct phone number so I can verify?",
            ],
            "refund_scam": [
                "Refund? For what? What is your name and customer support number?",
                "I don't remember any refund. Can you give me your official email and phone number?",
                "Which company is this refund from? What is the official website link?",
                "My son handles refunds. Can you give me your phone number so he can call you back?",
            ],
        }

        # ── MIDDLE STAGE — Ask for specific details: UPI, phone, email, link ──
        middle = {
            "generic": [
                "Okay I want to cooperate. What is the exact UPI ID I should send to?",
                "I need to verify first. What is the official phone number I can call back?",
                "My husband needs your details. What is your direct phone number and email?",
                "I want to do this properly. Can you send me the link on email? What is your email address?",
                "Wait let me write this down. What is the UPI ID and your phone number again?",
                "I need proof this is real. Can you share your employee ID and official email?",
                "My son will help me. Give me your phone number and the website link to check.",
                "Before I proceed, what is your name, employee ID, and callback number?",
                "I want to send the money but need the correct UPI ID. Can you repeat it clearly?",
                "Let me check with my bank first. What is your official phone number?",
                "Can you send me an official email about this? What email address should I reply to?",
                "I am at the bank. They want your phone number and employee ID. Can you share?",
            ],
        }

        # ── LATE STAGE — Demand all details, point out inconsistencies ──
        late = {
            "generic": [
                "Something is not right. Give me your supervisor's phone number to verify.",
                "My son checked and says I should get your phone number and email for records.",
                "I want to report this to the bank. What is your full name, phone number, and email?",
                "The bank says real officers give their phone number. What is your direct number?",
                "This feels wrong. My son wants your employee ID, phone number, and email address.",
                "I will file a complaint. Give me the official link and your contact number.",
                "Banks don't call like this. What is the official helpline number? And your badge number?",
                "Before I do anything, tell me your UPI ID, phone number, and official email again.",
                "My son is calling the police. Give me your number so they can contact you.",
                "I need all your details for my records — phone number, email, UPI ID, and employee ID.",
            ],
        }

        if stage == "early":
            pool = early.get(scam_type, [])
            if not pool:
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
        """Generate detailed agent notes with red flags and intelligence summary."""
        parts = []

        # Scam types
        if detected_scam_types:
            parts.append(f"Scam types detected: {', '.join(detected_scam_types)}.")

        # Red flags identified
        red_flags = self._identify_red_flags(conversation_history)
        if red_flags:
            parts.append(f"Red flags identified: {'; '.join(red_flags)}.")

        # Extracted intelligence
        intel = extracted_intelligence
        if intel.get("phoneNumbers"):
            parts.append(f"Phone numbers extracted: {', '.join(intel['phoneNumbers'])}.")
        if intel.get("upiIds"):
            parts.append(f"UPI IDs extracted: {', '.join(intel['upiIds'])}.")
        if intel.get("bankAccounts"):
            parts.append(f"Bank accounts extracted: {', '.join(intel['bankAccounts'])}.")
        if intel.get("phishingLinks"):
            parts.append(f"Phishing links extracted: {', '.join(intel['phishingLinks'])}.")
        if intel.get("emailAddresses"):
            parts.append(f"Email addresses extracted: {', '.join(intel['emailAddresses'])}.")

        # Conversation metrics
        msg_count = len(conversation_history)
        parts.append(f"Conversation: {msg_count} messages exchanged.")

        # Tactics observed
        tactics = self._identify_tactics(conversation_history)
        if tactics:
            parts.append(f"Scammer tactics observed: {', '.join(tactics)}.")

        return " ".join(parts) if parts else "Session logged. No definitive scam indicators found."

    def _identify_red_flags(self, conversation_history: List[Dict]) -> List[str]:
        """Identify specific red flags from the conversation."""
        flags = []
        scammer_msgs = [
            m.get("text", "").lower()
            for m in conversation_history
            if m.get("sender", "").lower() != "user"
        ]
        all_text = " ".join(scammer_msgs)

        # Time pressure
        if any(w in all_text for w in ["urgent", "immediately", "expire", "last chance",
                                        "time is running out", "hurry", "within 24 hours",
                                        "within 1 hour", "final notice"]):
            flags.append("Artificial time pressure and urgency")

        # Authority impersonation
        if any(w in all_text for w in ["rbi", "reserve bank", "government", "police",
                                        "cyber cell", "income tax", "court"]):
            flags.append("Impersonation of government/regulatory authority")
        if any(w in all_text for w in ["bank officer", "fraud department", "customer care",
                                        "manager", "supervisor", "senior officer"]):
            flags.append("Impersonation of bank/company official")

        # Sensitive info requests
        if any(w in all_text for w in ["share otp", "send otp", "tell otp", "otp",
                                        "pin", "cvv", "password", "mpin"]):
            flags.append("Request for sensitive credentials (OTP/PIN/CVV)")

        # Financial requests
        if any(w in all_text for w in ["send money", "transfer", "pay", "send rs",
                                        "verification payment", "processing fee"]):
            flags.append("Request for money transfer/payment")

        # Threatening language
        if any(w in all_text for w in ["blocked", "suspended", "frozen", "closed",
                                        "legal action", "arrest", "fine", "penalty",
                                        "blacklist", "seized"]):
            flags.append("Threatening with account suspension/legal action")

        # Suspicious links
        if any(w in all_text for w in ["click", "http", "link", "visit", "url"]):
            flags.append("Sharing suspicious links/URLs")

        # Too-good-to-be-true offers
        if any(w in all_text for w in ["won", "winner", "prize", "lottery",
                                        "cashback", "reward", "free", "discount"]):
            flags.append("Unrealistic offers/prizes as bait")

        # Info escalation (asking for more and more)
        sensitive_asks = sum(1 for msg in scammer_msgs
                          if any(w in msg for w in ["account", "number", "details", "verify", "share"]))
        if sensitive_asks >= 3:
            flags.append("Progressive escalation of information requests")

        return flags

    def _identify_tactics(self, conversation_history: List[Dict]) -> List[str]:
        """Identify scammer tactics from conversation."""
        tactics = set()
        for msg in conversation_history:
            if msg.get("sender", "").lower() != "user":
                text = msg.get("text", "").lower()
                if any(w in text for w in ["urgent", "immediately", "now", "expire", "hurry", "last chance"]):
                    tactics.add("urgency_pressure")
                if any(w in text for w in ["blocked", "suspended", "frozen", "legal", "arrest", "police"]):
                    tactics.add("threat_intimidation")
                if any(w in text for w in ["bank", "rbi", "government", "officer", "department", "customer care"]):
                    tactics.add("authority_impersonation")
                if any(w in text for w in ["otp", "pin", "cvv", "password", "verify"]):
                    tactics.add("credential_harvesting")
                if any(w in text for w in ["send money", "transfer", "pay", "upi"]):
                    tactics.add("financial_extraction")
                if any(w in text for w in ["click", "link", "http", "visit", "url"]):
                    tactics.add("phishing_link_distribution")
                if any(w in text for w in ["won", "prize", "cashback", "reward", "lottery", "free"]):
                    tactics.add("social_engineering_bait")
                if any(w in text for w in ["employee id", "sbi-", "my id", "badge", "reference"]):
                    tactics.add("fake_credential_presentation")
        return sorted(tactics)


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
