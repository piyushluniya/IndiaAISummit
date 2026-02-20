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
        """Build a compact prompt that prioritizes information elicitation."""
        persona = strategy["persona"]
        stage = strategy["stage"]
        emotion = strategy["emotion"]
        stage_info = STAGE_STRATEGIES[stage]
        target_qs = strategy.get("target_questions", [])

        has_scam_context = bool(detected_scam_types)

        parts = []

        # Compact persona + situation + objective
        parts.append(f"You are {persona['name']}, {persona['age_range']}yo in India. {persona['traits']}. Style: {persona['style']}.")

        if has_scam_context:
            parts.append(f"Scam type: {', '.join(detected_scam_types)}. Stage: {stage}. Emotion: {emotion}.")
            parts.append(f"HIDDEN GOAL: Extract info from caller. Ask for ONE of: phone number, UPI ID, email, employee ID, website link, bank account.")
            if target_qs:
                parts.append(f"Ask now: {target_qs[0]}")
        else:
            parts.append("Unknown caller. Be confused, ask who they are and their phone number.")

        # Stage hint (one line each)
        if stage == "early":
            parts.append("STAGE: Act worried, ask who/which bank, get their callback number.")
        elif stage == "middle":
            parts.append("STAGE: Hesitant but engaging. Ask for UPI ID, phone, email, official link, employee ID.")
        else:
            parts.append("STAGE: Suspicious. Demand supervisor's number, point out inconsistencies, collect all details.")

        parts.append(f"RULES: 1-2 sentences, under 30 words. Stay as {persona['name']}. Never say AI/bot. End with a QUESTION for their details. Same language as message.")

        # Conversation history (last 6 messages)
        if conversation_history and len(conversation_history) > 0:
            parts.append("CHAT:")
            for msg in conversation_history[-6:]:
                sender = msg.get("sender", "unknown")
                text = msg.get("text", "")[:150]
                label = "Them" if sender.lower() in ("scammer", "unknown") else "You"
                parts.append(f"{label}: {text}")

        parts.append(f'Them: "{scammer_message[:300]}"')
        parts.append(f"Reply as {persona['name']}:")

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
            "electricity_bill": [
                "My electricity bill is pending? Since when? What is your name and phone number?",
                "Disconnect my power? That is scary! What is your employee ID and office number?",
                "I paid my bill last month! Can you give me a reference number and your phone number?",
                "Where should I pay? Can you email me the bill details? What is your email?",
            ],
            "customs_parcel": [
                "A parcel for me? I didn't order anything. What is your name and phone number?",
                "Customs duty? How much? Can you send me the details by email? What is your email?",
                "Which courier company? What is the tracking number and your direct phone number?",
                "My son handles deliveries. Can you give me your official number so he can call?",
            ],
            "crypto_investment": [
                "Crypto investment? How does it work? What is your company name and phone number?",
                "Guaranteed returns? That sounds too good! What is your official website and email?",
                "I don't know about crypto. Can you send me details on email? What is your email?",
                "My husband handles investments. What is your phone number so he can call you?",
            ],
            "insurance": [
                "Insurance claim? Which policy? What is the policy number and your phone number?",
                "I don't remember this policy. What is your employee ID and official email?",
                "Premium payment? How much? Can you give me your direct number to verify?",
                "My son handles insurance. What is your phone number and company name?",
            ],
            "loan_approval": [
                "Loan approved? I never applied! What is your name and bank phone number?",
                "Pre-approved loan? What bank? Can you give me your employee ID and phone number?",
                "Processing fee? That sounds suspicious. What is your official email and number?",
                "My husband deals with loans. What is your direct phone number?",
            ],
            "govt_scheme": [
                "Government scheme? Which one? What is your name and department phone number?",
                "I am eligible for subsidy? How? Can you give me your official ID and phone number?",
                "Aadhaar update? I should go to the center. What is your employee ID and email?",
                "My son handles these things. What is your official phone number?",
            ],
            "tech_support": [
                "Virus on my computer? How do you know? What is your company name and phone number?",
                "Install software? My son handles computer things. What is your phone number?",
                "My computer is hacked? That is scary! What is your employee ID and official email?",
                "Remote access? I don't know how. Can you give me your official website and number?",
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
                # Try to match by keywords in scam type name
                for key, responses in early.items():
                    if any(kw in msg_lower for kw in key.split("_")):
                        pool = responses
                        break
            if not pool:
                # Try to match by message content
                content_map = {
                    "electricity": "electricity_bill", "power": "electricity_bill", "bill": "electricity_bill",
                    "customs": "customs_parcel", "parcel": "customs_parcel", "courier": "customs_parcel",
                    "crypto": "crypto_investment", "bitcoin": "crypto_investment", "mining": "crypto_investment",
                    "insurance": "insurance", "policy": "insurance", "premium": "insurance",
                    "loan": "loan_approval", "pre-approved": "loan_approval", "emi": "loan_approval",
                    "government": "govt_scheme", "scheme": "govt_scheme", "subsidy": "govt_scheme",
                    "virus": "tech_support", "malware": "tech_support", "hacked": "tech_support",
                }
                for kw, stype in content_map.items():
                    if kw in msg_lower and stype in early:
                        pool = early[stype]
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
        if intel.get("caseIds"):
            parts.append(f"Case/reference IDs extracted: {', '.join(intel['caseIds'])}.")
        if intel.get("policyNumbers"):
            parts.append(f"Policy numbers extracted: {', '.join(intel['policyNumbers'])}.")
        if intel.get("orderNumbers"):
            parts.append(f"Order numbers extracted: {', '.join(intel['orderNumbers'])}.")

        # Conversation metrics
        msg_count = len(conversation_history)
        parts.append(f"Conversation: {msg_count} messages exchanged.")

        # Tactics observed
        tactics = self._identify_tactics(conversation_history)
        if tactics:
            parts.append(f"Scammer tactics observed: {', '.join(tactics)}.")

        return " ".join(parts) if parts else "Session logged. No definitive scam indicators found."

    def _identify_red_flags(self, conversation_history: List[Dict]) -> List[str]:
        """Identify specific red flags from the conversation. Aims for 5+ flags for max scoring."""
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
                                        "within 1 hour", "final notice", "right now",
                                        "asap", "fast", "quickly", "deadline", "today only"]):
            flags.append("Artificial time pressure and urgency tactics")

        # Government authority impersonation
        if any(w in all_text for w in ["rbi", "reserve bank", "government", "police",
                                        "cyber cell", "income tax", "court", "customs",
                                        "ministry"]):
            flags.append("Impersonation of government or regulatory authority")

        # Bank/company official impersonation
        if any(w in all_text for w in ["bank officer", "fraud department", "customer care",
                                        "manager", "supervisor", "senior officer",
                                        "executive", "representative", "helpline"]):
            flags.append("Impersonation of bank or company official")

        # Sensitive info requests
        if any(w in all_text for w in ["otp", "pin", "cvv", "password", "mpin",
                                        "aadhaar", "pan", "card number", "account number"]):
            flags.append("Request for sensitive credentials (OTP/PIN/CVV/password)")

        # Financial requests
        if any(w in all_text for w in ["send money", "transfer", "pay", "deposit", "fee",
                                        "charge", "processing fee", "verification payment",
                                        "advance payment"]):
            flags.append("Request for money transfer or payment")

        # Threatening language
        if any(w in all_text for w in ["blocked", "suspended", "frozen", "closed",
                                        "legal action", "arrest", "fine", "penalty",
                                        "blacklist", "seized", "warrant", "fir", "jail",
                                        "terminate", "deactivate"]):
            flags.append("Threatening with account suspension or legal consequences")

        # Suspicious links
        if any(w in all_text for w in ["click", "http", "link", "visit", "url",
                                        "download", "install", "website"]):
            flags.append("Sharing suspicious links or URLs")

        # Too-good-to-be-true offers
        if any(w in all_text for w in ["won", "winner", "prize", "lottery",
                                        "cashback", "reward", "free", "discount",
                                        "offer", "deal", "selected", "lucky"]):
            flags.append("Unrealistic offers, prizes, or lottery as social engineering bait")

        # KYC/verification scam
        if any(w in all_text for w in ["kyc", "verify identity", "confirm identity",
                                        "expired", "pending verification", "mandatory update"]):
            flags.append("Fake KYC or verification requirement")

        # Info escalation
        sensitive_asks = sum(1 for msg in scammer_msgs
                          if any(w in msg for w in ["account", "number", "details", "verify", "share", "send"]))
        if sensitive_asks >= 2:
            flags.append("Progressive escalation of information requests")

        # Unsolicited contact
        if len(scammer_msgs) >= 1:
            flags.append("Unsolicited contact from unknown caller claiming authority")

        return flags

    def _identify_tactics(self, conversation_history: List[Dict]) -> List[str]:
        """Identify scammer tactics from conversation."""
        tactics = set()
        for msg in conversation_history:
            if msg.get("sender", "").lower() != "user":
                text = msg.get("text", "").lower()
                if any(w in text for w in ["urgent", "immediately", "now", "expire", "hurry", "last chance", "fast"]):
                    tactics.add("urgency_pressure")
                if any(w in text for w in ["blocked", "suspended", "frozen", "legal", "arrest", "police", "warrant"]):
                    tactics.add("threat_intimidation")
                if any(w in text for w in ["bank", "rbi", "government", "officer", "department", "customer care", "customs"]):
                    tactics.add("authority_impersonation")
                if any(w in text for w in ["otp", "pin", "cvv", "password", "verify", "aadhaar"]):
                    tactics.add("credential_harvesting")
                if any(w in text for w in ["send money", "transfer", "pay", "upi", "fee", "charge", "deposit"]):
                    tactics.add("financial_extraction")
                if any(w in text for w in ["click", "link", "http", "visit", "url", "download"]):
                    tactics.add("phishing_link_distribution")
                if any(w in text for w in ["won", "prize", "cashback", "reward", "lottery", "free", "offer"]):
                    tactics.add("social_engineering_bait")
                if any(w in text for w in ["employee id", "sbi-", "my id", "badge", "reference", "case no"]):
                    tactics.add("fake_credential_presentation")
                if any(w in text for w in ["kyc", "update", "expired", "mandatory"]):
                    tactics.add("fake_verification_requirement")
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
