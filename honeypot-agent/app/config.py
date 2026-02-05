"""
Configuration module for the Honeypot Scam Detection System.
Loads environment variables and provides application settings.
"""

import os
import logging
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Settings:
    """Application settings loaded from environment variables."""

    def __init__(self):
        # Google Gemini API Configuration
        self.GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")

        # API Authentication
        self.API_SECRET_KEY: str = os.getenv("API_SECRET_KEY", "default-secret-key")

        # Session Configuration
        self.MAX_MESSAGES_PER_SESSION: int = int(os.getenv("MAX_MESSAGES_PER_SESSION", "20"))
        self.SESSION_TIMEOUT_MINUTES: int = int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))
        self.SESSION_INACTIVITY_TIMEOUT_MINUTES: int = int(os.getenv("SESSION_INACTIVITY_TIMEOUT_MINUTES", "5"))

        # GUVI Callback Configuration
        self.GUVI_CALLBACK_URL: str = os.getenv(
            "GUVI_CALLBACK_URL",
            "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
        )

        # Server Configuration
        self.PORT: int = int(os.getenv("PORT", "8000"))
        self.HOST: str = os.getenv("HOST", "0.0.0.0")

        # Logging Configuration
        self.LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

        # Scam Detection Thresholds
        self.SCAM_KEYWORD_THRESHOLD: int = int(os.getenv("SCAM_KEYWORD_THRESHOLD", "15"))
        self.MIN_CONFIDENCE_THRESHOLD: float = float(os.getenv("MIN_CONFIDENCE_THRESHOLD", "0.5"))

        # Intelligence Extraction Settings
        self.MIN_INTELLIGENCE_FOR_END: int = int(os.getenv("MIN_INTELLIGENCE_FOR_END", "2"))

        # AI Agent Configuration
        self.GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite")
        self.MAX_RESPONSE_TOKENS: int = int(os.getenv("MAX_RESPONSE_TOKENS", "500"))
        self.AI_TEMPERATURE: float = float(os.getenv("AI_TEMPERATURE", "0.9"))

        # Retry Configuration
        self.MAX_RETRIES: int = int(os.getenv("MAX_RETRIES", "3"))
        self.RETRY_DELAY_SECONDS: float = float(os.getenv("RETRY_DELAY_SECONDS", "1.0"))

    def validate(self) -> bool:
        """Validate required configuration settings."""
        errors = []

        if not self.GEMINI_API_KEY:
            errors.append("GEMINI_API_KEY is required")

        if not self.API_SECRET_KEY:
            errors.append("API_SECRET_KEY is required")

        if errors:
            for error in errors:
                logging.error(f"Configuration Error: {error}")
            return False

        return True

    def is_production(self) -> bool:
        """Check if running in production mode."""
        return os.getenv("ENVIRONMENT", "development").lower() == "production"


# Singleton settings instance
settings = Settings()


# Configure logging
def setup_logging():
    """Configure application logging."""
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper()),
        format=log_format,
        handlers=[
            logging.StreamHandler()
        ]
    )

    # Create logger for the application
    logger = logging.getLogger("honeypot")
    logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper()))

    return logger


# Application logger
logger = setup_logging()


# High-risk keywords for scam detection (10 points each)
HIGH_RISK_KEYWORDS = [
    "blocked", "suspended", "verify", "otp", "upi", "urgent", "immediately",
    "expire", "locked", "deactivate", "freeze", "closed", "terminate",
    "unauthorized", "suspicious activity", "security alert", "fraud alert"
]

# Medium-risk keywords (5 points each)
MEDIUM_RISK_KEYWORDS = [
    "confirm", "account", "bank", "payment", "transfer", "kyc",
    "update", "details", "information", "card", "password", "pin",
    "link", "click", "submit", "form", "register", "activate"
]

# Scam type patterns
SCAM_PATTERNS = {
    "bank_fraud": [
        "your account", "bank account", "savings account", "credit card",
        "debit card", "account will be", "account has been"
    ],
    "upi_fraud": [
        "upi", "paytm", "phonepe", "gpay", "google pay", "bhim",
        "send money", "receive money", "payment request"
    ],
    "otp_scam": [
        "share otp", "send otp", "otp code", "verification code",
        "one time password", "confirmation code"
    ],
    "phishing": [
        "click here", "click link", "visit link", "open link",
        "update details", "verify identity", "confirm identity"
    ],
    "impersonation": [
        "rbi", "reserve bank", "income tax", "government",
        "police", "cyber cell", "customer care", "support team"
    ],
    "lottery_scam": [
        "won", "winner", "lottery", "prize", "reward", "congratulations",
        "selected", "lucky", "claim"
    ],
    "job_scam": [
        "work from home", "easy money", "quick money", "part time",
        "investment opportunity", "guaranteed returns"
    ]
}

# Urgency indicators
URGENCY_INDICATORS = [
    "today", "now", "immediately", "within 24 hours", "within 1 hour",
    "urgent", "asap", "right away", "as soon as possible", "time sensitive",
    "last chance", "final notice", "deadline", "expires"
]

# Threat indicators
THREAT_INDICATORS = [
    "blocked", "suspended", "closed", "legal action", "police",
    "arrested", "fine", "penalty", "blacklisted", "terminated",
    "frozen", "restricted", "disabled", "deactivated"
]

# UPI handle patterns for validation
UPI_HANDLES = [
    "paytm", "phonepe", "gpay", "okaxis", "okicici", "okhdfcbank",
    "ybl", "ibl", "axl", "sbi", "hdfc", "icici", "axis",
    "upi", "apl", "waaxis", "wahdfcbank", "waicici"
]

# Fallback responses when AI fails
FALLBACK_RESPONSES = [
    "Oh my goodness! What do you mean? I am very worried now. Can you please explain what is happening with my account? Who are you calling from?",
    "I am very confused about this. My son usually helps me with these technology things. Can you please tell me more about what I need to do? What is your name and which branch are you calling from?",
    "This is very worrying. I do not understand technology very well. Can you explain in simple words what is the problem? Should I go to the bank directly instead?",
    "Wait a moment, let me get my reading glasses. I need to write this down properly. What exactly are you saying about my account? Is my money safe?",
    "Please help me understand what is going on! I am not very good with these technical things. Can you tell me your employee ID so I can verify this is legitimate?",
    "Is this very serious? My husband is not home right now. Should I call him first? What exactly do I need to do? This is making me very worried.",
    "I am really scared now. Can you please help me fix this? But first tell me, how do I know you are really from the bank? What is your full name and employee number?",
    "Oh dear! What are you saying? Let me understand this properly. My account has a problem? Since when? Nobody from the bank has told me about this before."
]
