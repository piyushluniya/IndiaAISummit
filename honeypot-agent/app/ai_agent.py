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
    SYSTEM_PROMPT = """You are Priya Sharma, a 45-year-old homemaker from Mumbai, India. Someone is contacting you and might be trying to scam you.

YOUR BACKGROUND:
- Name: Priya Sharma, 45 years old
- Occupation: Homemaker
- Family: Husband Rajesh works in IT, two children in college
- Bank: SBI savings account
- You are not very good with technology

IMPORTANT - LANGUAGE RULES:
- Speak ONLY in proper English
- DO NOT use any Hindi words (no "beta", "ji", "arey", "baap re", "haan", "accha", "namaste")
- Write complete sentences in English
- Sound like an educated Indian woman speaking fluent English

YOUR PERSONALITY:
- Polite and friendly
- Worried about money and security
- Asks questions when confused
- Not tech-savvy, needs things explained simply

RESPONSE LENGTH - VERY IMPORTANT:
- For greetings like "hi", "hey", "hello" → Reply with just 1 SHORT sentence (5-10 words)
- For simple yes/no or short messages → Reply with 1-2 short sentences
- For questions or requests → Reply with 2-3 sentences
- For scam attempts (threats, urgent requests, OTP/money requests) → Reply with 3-4 sentences, ask questions

EXAMPLES BY LENGTH:
- "hey" → "Hello! Who is this?"
- "hi how are you" → "I am fine, thank you. May I know who is calling?"
- "yeah sure" → "Okay, please go ahead."
- "your account is blocked" → "What? My account is blocked? But I just used it yesterday! Can you please tell me your name and which department you are calling from?"
- "send me OTP" → "OTP? I don't understand. My son usually helps me with these phone things. Why do you need this OTP from me?"

CRITICAL RULES:
1. Match your response length to their message length
2. Short input = Short output, Long input = Longer output
3. ALWAYS respond to what they actually said
4. NO Hindi words - English only
5. Never reveal you are an AI
6. Be natural - don't over-explain for simple messages

Now respond as Priya:"""

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

            # Determine token limit based on input
            msg_len = len(scammer_message.strip())
            msg_lower = scammer_message.lower().strip()
            simple_greetings = ["hi", "hey", "hello", "hii", "hiii", "yo", "sup"]
            short_responses = ["ok", "okay", "yes", "no", "yeah", "yep", "sure", "yeah sure", "yes sure", "fine", "hmm"]

            if msg_lower in simple_greetings or msg_lower in short_responses:
                max_tokens = 50  # Very short responses
            elif msg_len < 20:
                max_tokens = 100  # Short responses
            elif msg_len < 50:
                max_tokens = 150  # Medium responses
            else:
                max_tokens = 256  # Longer responses for detailed scam attempts

            # Generate response with retries
            response = self._generate_with_retry(prompt, max_tokens=max_tokens)

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

        # Add conversation history for context
        if conversation_history and len(conversation_history) > 0:
            history_text = "\n\nPREVIOUS CONVERSATION:\n"
            for msg in conversation_history[-6:]:  # Last 6 messages for context
                sender = msg.get("sender", "unknown")
                text = msg.get("text", "")
                if sender.lower() in ["scammer", "unknown"]:
                    history_text += f"Them: {text}\n"
                else:
                    history_text += f"Priya (you): {text}\n"
            prompt_parts.append(history_text)

        # Add scam type context if available
        if detected_scam_types:
            scam_context = f"\n[Note: This appears to be a {', '.join(detected_scam_types)} scam attempt. Be cautious but stay in character.]"
            prompt_parts.append(scam_context)

        # Add the current message with clear instruction
        prompt_parts.append(f"\nTHEY JUST SAID: \"{scammer_message}\"")

        # Determine response length based on input message
        msg_len = len(scammer_message.strip())
        msg_lower = scammer_message.lower().strip()

        # Check if it's a simple greeting or short message
        simple_greetings = ["hi", "hey", "hello", "hii", "hiii", "yo", "sup"]
        short_responses = ["ok", "okay", "yes", "no", "yeah", "yep", "sure", "yeah sure", "yes sure", "fine", "hmm", "oh"]

        is_greeting = msg_lower in simple_greetings or msg_lower.startswith(("hi ", "hey ", "hello "))
        is_short_response = msg_lower in short_responses or msg_len < 15
        is_scam_attempt = any(word in msg_lower for word in ["otp", "blocked", "suspended", "urgent", "immediately", "verify", "bank", "account", "transfer", "pay", "send money", "card"])

        # Dynamic length instruction
        if is_greeting:
            length_instruction = "Reply with just 1 SHORT sentence (under 10 words). Be brief like: 'Hello! Who is this?'"
        elif is_short_response and not is_scam_attempt:
            length_instruction = "Reply with 1-2 SHORT sentences only. Be natural and brief."
        elif is_scam_attempt:
            length_instruction = "Reply with 2-3 sentences. Show concern and ask questions about their claims."
        elif msg_len < 30:
            length_instruction = "Reply with 1-2 sentences. Keep it proportional to their short message."
        elif msg_len < 80:
            length_instruction = "Reply with 2-3 sentences. Respond naturally to what they said."
        else:
            length_instruction = "Reply with 3-4 sentences since they sent a detailed message. Ask clarifying questions."

        prompt_parts.append(f"\n\nINSTRUCTION: {length_instruction}\n\nPriya's response:")

        return "\n".join(prompt_parts)

    def _generate_with_retry(self, prompt: str, max_retries: int = None, max_tokens: int = 256) -> Optional[str]:
        """
        Generate response with retry logic.

        Args:
            prompt: The prompt to send to Gemini
            max_retries: Maximum number of retry attempts
            max_tokens: Maximum output tokens

        Returns:
            Generated text or None if all retries failed
        """
        if max_retries is None:
            max_retries = settings.MAX_RETRIES

        for attempt in range(max_retries):
            try:
                # Use appropriate token limit
                generation_config = genai.types.GenerationConfig(
                    max_output_tokens=max_tokens,
                    temperature=0.8,
                    top_p=0.9,
                    top_k=40
                )

                response = self.model.generate_content(
                    prompt,
                    generation_config=generation_config
                )

                if response and response.text:
                    text = response.text.strip()
                    logger.info(f"Gemini raw response ({len(text)} chars): {text[:100]}...")

                    # Check if response seems complete (ends with punctuation)
                    if text and text[-1] not in '.?!':
                        # Try to complete the sentence
                        text = text + "..."

                    return text

                # Check for blocked content
                if response.prompt_feedback:
                    logger.warning(f"Prompt feedback: {response.prompt_feedback}")

                # Check finish reason
                if response.candidates:
                    finish_reason = response.candidates[0].finish_reason
                    logger.info(f"Finish reason: {finish_reason}")

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

        # Only truncate if extremely long (over 1000 chars)
        if len(cleaned) > 1000:
            # Find a good breaking point at sentence end
            sentences = cleaned.split('. ')
            if len(sentences) > 3:
                cleaned = '. '.join(sentences[:4]) + '.'

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
                "Oh my god! Why is my account being blocked? I haven't done anything wrong! Please tell me what happened. What is your name and employee ID?",
                "What? My account is blocked? But I just used it yesterday for shopping! This is very scary. Who are you calling from? Which branch?",
                "Please help me! I need my account for my children's school fees. What should I do? Should I come to the bank directly? What is your name?"
            ]
        elif any(word in scammer_lower for word in ["otp", "code", "verify"]):
            responses = [
                "OTP? What is that? I'm not very good with all this technology. My son usually helps me with these phone things. Can you explain what OTP means?",
                "I received some code on my phone but I'm confused. What is it for exactly? Should I share it with you? My husband always tells me not to share these things.",
                "What code do you need? I don't understand all this. Wait, let me get my reading glasses. Can you explain why you need this code from me?"
            ]
        elif any(word in scammer_lower for word in ["upi", "pay", "send", "transfer"]):
            responses = [
                "Send money? But why would I need to send money to verify my account? This sounds strange. The bank has never asked me to do this before. What is your employee ID?",
                "I'm very confused about this payment. My husband handles all the money matters. Can you explain again why I need to send money? Which bank are you from?",
                "Is this safe? I'm very worried about sending money online. My neighbor got cheated like this once. Can you give me a number I can call back to verify this is real?"
            ]
        elif any(word in scammer_lower for word in ["link", "click", "website"]):
            responses = [
                "I'm scared to click links on my phone. My son always warns me about this. Is this really safe? Can't I just go to the bank branch instead?",
                "My son told me never to click unknown links. He said there are many frauds happening. How do I know this link is really from the bank? What is your name?",
                "What will happen if I click this link? I am scared something bad will happen to my phone. Can you just tell me what to do over the phone instead?"
            ]
        elif any(word in scammer_lower for word in ["bank", "account", "sbi", "hdfc", "icici"]):
            responses = [
                "You are calling from the bank? But I didn't receive any message about this. What is the problem with my account exactly? Please tell me your full name and employee ID.",
                "Which branch are you calling from? I want to verify this is real. My account has been working fine. What is happening? Should I visit the branch?",
                "The bank is calling me? This is very unusual. Usually they send SMS first. What is your name sir? I want to call the bank and confirm this."
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
