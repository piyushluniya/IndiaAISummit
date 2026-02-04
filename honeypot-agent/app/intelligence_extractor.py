"""
Intelligence Extraction Module for the Honeypot System.
Extracts phone numbers, UPI IDs, bank accounts, links, and suspicious keywords.
"""

import re
from typing import List, Set, Dict
from .models import IntelligenceData
from .config import logger, UPI_HANDLES, HIGH_RISK_KEYWORDS, MEDIUM_RISK_KEYWORDS


class IntelligenceExtractor:
    """
    Extracts actionable intelligence from scammer messages.
    Uses regex patterns to identify phone numbers, UPI IDs, accounts, links, etc.
    """

    # Compiled regex patterns
    PATTERNS = {
        # Indian phone numbers: +91, 0, or direct 10 digits starting with 6-9
        "phone_indian": re.compile(
            r'(?:(?:\+91|91|0)?[-\s]?)?([6-9]\d{9})(?!\d)',
            re.IGNORECASE
        ),
        # International phone numbers
        "phone_intl": re.compile(
            r'\+(?!91)(\d{1,3})[-\s]?(\d{7,14})',
            re.IGNORECASE
        ),
        # UPI IDs: India-specific format (username@handle)
        # Matches: scammer@upi, raj.paytm@ybl, john123@okaxis
        "upi_id": re.compile(
            r'\b([a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64})\b',
            re.IGNORECASE
        ),
        # Bank account numbers (9-18 digits)
        "bank_account": re.compile(
            r'\b(\d{9,18})\b'
        ),
        # URLs/Links
        "url": re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        ),
        # Short URLs
        "short_url": re.compile(
            r'\b(?:bit\.ly|goo\.gl|t\.co|tinyurl\.com|is\.gd|buff\.ly|ow\.ly|rebrand\.ly)/[a-zA-Z0-9]+\b',
            re.IGNORECASE
        ),
        # IFSC codes (for context)
        "ifsc": re.compile(
            r'\b([A-Z]{4}0[A-Z0-9]{6})\b',
            re.IGNORECASE
        ),
        # Email addresses
        "email": re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
    }

    # Context words that indicate a number is a bank account
    BANK_CONTEXT_WORDS = [
        "account", "a/c", "acc", "bank", "savings", "current",
        "deposit", "transfer", "ifsc", "branch"
    ]

    # Known UPI handles for validation
    UPI_VALID_HANDLES = set(UPI_HANDLES)

    def __init__(self):
        """Initialize the intelligence extractor."""
        self.all_keywords = set(
            k.lower() for k in HIGH_RISK_KEYWORDS + MEDIUM_RISK_KEYWORDS
        )
        logger.info("IntelligenceExtractor initialized")

    def extract(self, message: str) -> IntelligenceData:
        """
        Extract all intelligence from a message.

        Args:
            message: Message text to analyze

        Returns:
            IntelligenceData object with extracted information
        """
        intelligence = IntelligenceData()

        # Extract phone numbers
        intelligence.phoneNumbers = self._extract_phone_numbers(message)

        # Extract UPI IDs
        intelligence.upiIds = self._extract_upi_ids(message)

        # Extract bank accounts
        intelligence.bankAccounts = self._extract_bank_accounts(message)

        # Extract URLs/links
        intelligence.phishingLinks = self._extract_urls(message)

        # Extract suspicious keywords
        intelligence.suspiciousKeywords = self._extract_keywords(message)

        # Log extraction results
        total_items = intelligence.total_items()
        if total_items > 0:
            logger.info(
                f"Extracted intelligence: {len(intelligence.phoneNumbers)} phones, "
                f"{len(intelligence.upiIds)} UPIs, {len(intelligence.bankAccounts)} accounts, "
                f"{len(intelligence.phishingLinks)} links, {len(intelligence.suspiciousKeywords)} keywords"
            )

        return intelligence

    def _extract_phone_numbers(self, message: str) -> List[str]:
        """Extract phone numbers from the message."""
        phones = set()

        # Extract Indian phone numbers
        for match in self.PATTERNS["phone_indian"].finditer(message):
            number = match.group(1)
            if self._is_valid_indian_phone(number):
                # Normalize to 10 digits
                phones.add(number)

        # Extract international numbers
        for match in self.PATTERNS["phone_intl"].finditer(message):
            country_code = match.group(1)
            number = match.group(2)
            full_number = f"+{country_code}{number}"
            phones.add(full_number)

        return list(phones)

    def _is_valid_indian_phone(self, number: str) -> bool:
        """Validate Indian phone number."""
        # Must be exactly 10 digits
        if len(number) != 10:
            return False
        # Must start with 6, 7, 8, or 9
        if number[0] not in "6789":
            return False
        # Should not be all same digits (e.g., 9999999999)
        if len(set(number)) == 1:
            return False
        # Should not be sequential
        if number in "6789012345" or number in "5432109876":
            return False
        return True

    def _extract_upi_ids(self, message: str) -> List[str]:
        """Extract UPI IDs from the message."""
        upi_ids = set()

        for match in self.PATTERNS["upi_id"].finditer(message):
            upi_id = match.group(1).lower()

            # Validate the handle part
            if self._is_valid_upi_id(upi_id):
                upi_ids.add(upi_id)

        return list(upi_ids)

    def _is_valid_upi_id(self, upi_id: str) -> bool:
        """Validate UPI ID format."""
        if "@" not in upi_id:
            return False

        username, handle = upi_id.rsplit("@", 1)

        # Username should be at least 3 characters
        if len(username) < 3:
            return False

        # Handle should be a known UPI handle or look like one
        handle_lower = handle.lower()

        # Check against known handles
        for valid_handle in self.UPI_VALID_HANDLES:
            if valid_handle in handle_lower:
                return True

        # Allow if handle looks legitimate (bank-like suffix)
        bank_suffixes = ["bank", "axis", "hdfc", "icici", "sbi", "pnb", "bob", "canara"]
        for suffix in bank_suffixes:
            if suffix in handle_lower:
                return True

        return False

    def _extract_bank_accounts(self, message: str) -> List[str]:
        """Extract bank account numbers from the message."""
        accounts = set()
        message_lower = message.lower()

        # Check if message has bank-related context
        has_bank_context = any(
            word in message_lower for word in self.BANK_CONTEXT_WORDS
        )

        for match in self.PATTERNS["bank_account"].finditer(message):
            number = match.group(1)

            # Only extract if there's bank context or number is in typical bank account range
            if has_bank_context and self._is_likely_bank_account(number, message, match.start()):
                accounts.add(number)

        return list(accounts)

    def _is_likely_bank_account(self, number: str, message: str, position: int) -> bool:
        """
        Determine if a number is likely a bank account.

        Args:
            number: The extracted number
            message: Full message text
            position: Position of number in message

        Returns:
            True if likely a bank account
        """
        # Filter out phone numbers (10 digits starting with 6-9)
        if len(number) == 10 and number[0] in "6789":
            return False

        # Filter out very long numbers (probably not accounts)
        if len(number) > 18:
            return False

        # Check surrounding context (50 chars before)
        context_start = max(0, position - 50)
        context = message[context_start:position].lower()

        # If surrounded by account-related words, likely an account
        if any(word in context for word in self.BANK_CONTEXT_WORDS):
            return True

        # If number is 11-16 digits, common for Indian bank accounts
        if 11 <= len(number) <= 16:
            return True

        return False

    def _extract_urls(self, message: str) -> List[str]:
        """Extract URLs and links from the message."""
        urls = set()

        # Extract full URLs
        for match in self.PATTERNS["url"].finditer(message):
            url = match.group(0)
            # Clean trailing punctuation
            url = url.rstrip(".,;:!?)")
            urls.add(url)

        # Extract short URLs
        for match in self.PATTERNS["short_url"].finditer(message):
            urls.add(match.group(0))

        return list(urls)

    def _extract_keywords(self, message: str) -> List[str]:
        """Extract suspicious keywords from the message."""
        keywords = set()
        message_lower = message.lower()

        for keyword in self.all_keywords:
            if keyword in message_lower:
                keywords.add(keyword)

        return list(keywords)

    def extract_from_history(self, history: List[Dict]) -> IntelligenceData:
        """
        Extract intelligence from entire conversation history.

        Args:
            history: List of message dictionaries

        Returns:
            Combined IntelligenceData from all messages
        """
        combined = IntelligenceData()

        for msg in history:
            if msg.get("sender", "").lower() in ["scammer", "unknown"]:
                text = msg.get("text", "")
                if text:
                    msg_intel = self.extract(text)
                    combined.merge(msg_intel)

        return combined

    def get_ifsc_codes(self, message: str) -> List[str]:
        """
        Extract IFSC codes from message (for additional context).

        Args:
            message: Message text

        Returns:
            List of IFSC codes
        """
        codes = []
        for match in self.PATTERNS["ifsc"].finditer(message):
            code = match.group(1).upper()
            codes.append(code)
        return codes

    def get_emails(self, message: str) -> List[str]:
        """
        Extract email addresses from message.

        Args:
            message: Message text

        Returns:
            List of email addresses
        """
        emails = []
        for match in self.PATTERNS["email"].finditer(message):
            emails.append(match.group(0))
        return emails


# Singleton instance
intelligence_extractor = IntelligenceExtractor()


def extract_intelligence(message: str) -> IntelligenceData:
    """
    Convenience function to extract intelligence from a message.

    Args:
        message: Message text to analyze

    Returns:
        IntelligenceData object
    """
    return intelligence_extractor.extract(message)


def extract_from_conversation(history: List[Dict]) -> IntelligenceData:
    """
    Convenience function to extract intelligence from conversation history.

    Args:
        history: List of message dictionaries

    Returns:
        Combined IntelligenceData
    """
    return intelligence_extractor.extract_from_history(history)
