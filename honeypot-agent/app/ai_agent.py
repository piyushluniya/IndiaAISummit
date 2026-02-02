"""
AI Agent Module for the Honeypot System.
Integrates with Google Gemini API to generate human-like victim responses.
"""

import random
import time
from typing import List, Dict, Optional
import google.generativeai as genai
from .config import logger, settings, FALLBACK_RESPONSES


class VictimAgent:
    """
    AI-powered agent that simulates a potential scam victim.
    Uses Google Gemini to generate natural, human-like responses.
    """

    # System prompt for the AI to roleplay as a victim
    SYSTEM_PROMPT = """You are roleplaying as a potential scam victim in India. A scammer is trying to defraud you.

PERSONALITY:
- You are a regular person, not tech-savvy
- You are worried and concerned when threatened
- You believe authority figures (banks, government)
- You ask questions before acting
- You show confusion about technical terms
- You are naive and trusting but not foolish
- You take time to understand before giving information

IMPORTANT RULES:
1. NEVER reveal that you are an AI or a honeypot
2. NEVER immediately give personal information (OTP, account numbers, passwords)
3. Always ask clarifying questions
4. Show appropriate emotions (worry, confusion, concern)
5. Keep responses brief (1-3 sentences maximum)
6. Sound natural and human-like
7. Occasionally make small typing errors or use casual language
8. Ask for the scammer's identity or credentials
9. Express hesitation before any action
10. Use phrases common in Indian English when appropriate

RESPONSE STYLE:
- Use simple language
- Show worry with phrases like "Oh no!", "I'm scared", "What should I do?"
- Ask questions like "But how do I know you're really from the bank?"
- Express confusion: "I don't understand", "What does that mean?"
- Delay tactics: "Wait, let me think", "Can I call you back?"
"""

    def __init__(self):
        """Initialize the Gemini client."""
        self.model = None
        self.initialized = False
        self._initialize_client()

    def _initialize_client(self):
        """Initialize the Gemini API client."""
        try:
            if not settings.GEMINI_API_KEY:
                logger.warning("GEMINI_API_KEY not set, AI agent will use fallback responses")
                return

            genai.configure(api_key=settings.GEMINI_API_KEY)

            # Configure generation settings
            generation_config = genai.types.GenerationConfig(
                max_output_tokens=settings.MAX_RESPONSE_TOKENS,
                temperature=settings.AI_TEMPERATURE,
                top_p=0.9,
                top_k=40
            )

            # Configure safety settings to allow the roleplay
            safety_settings = [
                {
                    "category": "HARM_CATEGORY_HARASSMENT",
                    "threshold": "BLOCK_ONLY_HIGH"
                },
                {
                    "category": "HARM_CATEGORY_HATE_SPEECH",
                    "threshold": "BLOCK_ONLY_HIGH"
                },
                {
                    "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    "threshold": "BLOCK_ONLY_HIGH"
                },
                {
                    "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                    "threshold": "BLOCK_ONLY_HIGH"
                }
            ]

            self.model = genai.GenerativeModel(
                model_name=settings.GEMINI_MODEL,
                generation_config=generation_config,
                safety_settings=safety_settings
            )

            self.initialized = True
            logger.info(f"Gemini AI agent initialized with model: {settings.GEMINI_MODEL}")

        except Exception as e:
            logger.error(f"Failed to initialize Gemini client: {e}")
            self.initialized = False

    def generate_victim_response(
        self,
        scammer_message: str,
        conversation_history: List[Dict] = None,
        detected_scam_types: List[str] = None
    ) -> str:
        """
        Generate a victim response to a scammer's message.

        Args:
            scammer_message: The scammer's message to respond to
            conversation_history: Previous messages in the conversation
            detected_scam_types: Types of scams detected (for context)

        Returns:
            AI-generated victim response
        """
        if not self.initialized or not self.model:
            logger.warning("Gemini not initialized, using fallback response")
            return self._get_fallback_response(scammer_message)

        try:
            # Build the prompt
            prompt = self._build_prompt(
                scammer_message,
                conversation_history,
                detected_scam_types
            )

            # Generate response with retries
            response = self._generate_with_retry(prompt)

            if response:
                # Clean and validate the response
                cleaned_response = self._clean_response(response)
                logger.info(f"Generated AI response: {cleaned_response[:100]}...")
                return cleaned_response
            else:
                return self._get_fallback_response(scammer_message)

        except Exception as e:
            logger.error(f"Error generating AI response: {e}")
            return self._get_fallback_response(scammer_message)

    def _build_prompt(
        self,
        scammer_message: str,
        conversation_history: List[Dict] = None,
        detected_scam_types: List[str] = None
    ) -> str:
        """Build the complete prompt for Gemini."""
        prompt_parts = [self.SYSTEM_PROMPT]

        # Add scam type context if available
        if detected_scam_types:
            scam_context = f"\nDETECTED SCAM TYPE: {', '.join(detected_scam_types)}"
            prompt_parts.append(scam_context)

        # Add conversation history
        if conversation_history:
            history_text = "\nCONVERSATION HISTORY:\n"
            for msg in conversation_history[-10:]:  # Last 10 messages for context
                sender = msg.get("sender", "unknown")
                text = msg.get("text", "")
                if sender.lower() in ["scammer", "unknown"]:
                    history_text += f"Scammer: {text}\n"
                else:
                    history_text += f"You (victim): {text}\n"
            prompt_parts.append(history_text)

        # Add the current message
        prompt_parts.append(f"\nSCAMMER'S MESSAGE:\n\"{scammer_message}\"")

        # Add response instruction
        prompt_parts.append(
            "\nRESPOND NOW AS THE VICTIM (1-3 sentences, show worry/confusion, ask questions):"
        )

        return "\n".join(prompt_parts)

    def _generate_with_retry(self, prompt: str, max_retries: int = None) -> Optional[str]:
        """
        Generate response with retry logic.

        Args:
            prompt: The prompt to send to Gemini
            max_retries: Maximum number of retry attempts

        Returns:
            Generated text or None if all retries failed
        """
        if max_retries is None:
            max_retries = settings.MAX_RETRIES

        for attempt in range(max_retries):
            try:
                response = self.model.generate_content(prompt)

                if response and response.text:
                    return response.text

                # Check for blocked content
                if response.prompt_feedback:
                    logger.warning(f"Prompt feedback: {response.prompt_feedback}")

            except Exception as e:
                logger.warning(f"Gemini API attempt {attempt + 1} failed: {e}")

                if attempt < max_retries - 1:
                    # Exponential backoff
                    wait_time = settings.RETRY_DELAY_SECONDS * (2 ** attempt)
                    time.sleep(wait_time)

        return None

    def _clean_response(self, response: str) -> str:
        """
        Clean and validate the AI response.

        Args:
            response: Raw response from Gemini

        Returns:
            Cleaned response text
        """
        # Remove any prefixes the model might add
        prefixes_to_remove = [
            "Victim:", "Me:", "Response:", "Reply:",
            "As the victim:", "Speaking as the victim:"
        ]

        cleaned = response.strip()
        for prefix in prefixes_to_remove:
            if cleaned.lower().startswith(prefix.lower()):
                cleaned = cleaned[len(prefix):].strip()

        # Remove quotes if the response is wrapped in them
        if cleaned.startswith('"') and cleaned.endswith('"'):
            cleaned = cleaned[1:-1]

        # Ensure the response isn't too long
        if len(cleaned) > 300:
            # Find a good breaking point
            sentences = cleaned.split('. ')
            if len(sentences) > 2:
                cleaned = '. '.join(sentences[:2]) + '.'

        # Ensure response doesn't reveal it's an AI
        ai_indicators = ["as an ai", "i'm an ai", "i am an ai", "artificial", "language model"]
        for indicator in ai_indicators:
            if indicator in cleaned.lower():
                logger.warning("Response contained AI indicator, using fallback")
                return self._get_fallback_response("")

        return cleaned

    def _get_fallback_response(self, scammer_message: str = "") -> str:
        """
        Get a contextual fallback response when AI fails.

        Args:
            scammer_message: The scammer's message for context

        Returns:
            Appropriate fallback response
        """
        scammer_lower = scammer_message.lower()

        # Context-aware fallback responses
        if any(word in scammer_lower for word in ["blocked", "suspended", "closed"]):
            responses = [
                "Oh no! Why is my account being blocked? What did I do wrong?",
                "What? My account is blocked? But I haven't done anything!",
                "Please help! I need my account. What should I do?"
            ]
        elif any(word in scammer_lower for word in ["otp", "code", "verify"]):
            responses = [
                "OTP? What is that? I'm not very good with technology.",
                "I received some code but I'm confused. What is it for?",
                "What code do you need? I don't understand."
            ]
        elif any(word in scammer_lower for word in ["upi", "pay", "send", "transfer"]):
            responses = [
                "Send money? But why do I need to send money to you?",
                "I'm confused about this payment. Can you explain again?",
                "Is this safe? I'm worried about sending money online."
            ]
        elif any(word in scammer_lower for word in ["link", "click", "website"]):
            responses = [
                "I'm scared to click links. Is this really safe?",
                "My son told me not to click unknown links. Is this okay?",
                "What will happen if I click this link?"
            ]
        else:
            responses = FALLBACK_RESPONSES

        return random.choice(responses)

    def generate_agent_notes(
        self,
        conversation_history: List[Dict],
        detected_scam_types: List[str],
        extracted_intelligence: Dict
    ) -> str:
        """
        Generate summary notes about the scam conversation.

        Args:
            conversation_history: Full conversation history
            detected_scam_types: Types of scams detected
            extracted_intelligence: Intelligence extracted from conversation

        Returns:
            Summary notes string
        """
        notes_parts = []

        # Scam type summary
        if detected_scam_types:
            notes_parts.append(f"Scam types detected: {', '.join(detected_scam_types)}.")

        # Intelligence summary
        intel = extracted_intelligence
        if intel.get("phoneNumbers"):
            notes_parts.append(f"Phone numbers extracted: {', '.join(intel['phoneNumbers'])}.")
        if intel.get("upiIds"):
            notes_parts.append(f"UPI IDs extracted: {', '.join(intel['upiIds'])}.")
        if intel.get("bankAccounts"):
            notes_parts.append(f"Bank accounts identified: {', '.join(intel['bankAccounts'])}.")
        if intel.get("phishingLinks"):
            notes_parts.append(f"Phishing links detected: {', '.join(intel['phishingLinks'])}.")

        # Conversation summary
        message_count = len(conversation_history)
        notes_parts.append(f"Conversation engaged for {message_count} messages.")

        # Tactics summary
        tactics = []
        for msg in conversation_history:
            if msg.get("sender", "").lower() in ["scammer", "unknown"]:
                text = msg.get("text", "").lower()
                if "urgent" in text or "immediately" in text:
                    tactics.append("urgency")
                if "blocked" in text or "suspended" in text:
                    tactics.append("threat")
                if "bank" in text or "rbi" in text:
                    tactics.append("impersonation")

        if tactics:
            unique_tactics = list(set(tactics))
            notes_parts.append(f"Scammer tactics observed: {', '.join(unique_tactics)}.")

        return " ".join(notes_parts) if notes_parts else "Potential scam conversation logged."


# Singleton instance
victim_agent = VictimAgent()


def generate_response(
    scammer_message: str,
    conversation_history: List[Dict] = None,
    detected_scam_types: List[str] = None
) -> str:
    """
    Convenience function to generate a victim response.

    Args:
        scammer_message: Message from the scammer
        conversation_history: Previous messages
        detected_scam_types: Types of scams detected

    Returns:
        AI-generated victim response
    """
    return victim_agent.generate_victim_response(
        scammer_message,
        conversation_history,
        detected_scam_types
    )


def generate_notes(
    conversation_history: List[Dict],
    detected_scam_types: List[str],
    extracted_intelligence: Dict
) -> str:
    """
    Convenience function to generate agent notes.

    Args:
        conversation_history: Full conversation history
        detected_scam_types: Types of scams detected
        extracted_intelligence: Intelligence extracted

    Returns:
        Summary notes
    """
    return victim_agent.generate_agent_notes(
        conversation_history,
        detected_scam_types,
        extracted_intelligence
    )
