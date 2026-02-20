"""
Advanced Intelligence Extraction Module for the Honeypot System.
Extracts phone numbers, UPI IDs, bank accounts, links, emails, money amounts,
and suspicious keywords — including obfuscated content.
"""

import re
from typing import List, Dict
from .models import IntelligenceData
from .config import logger, UPI_HANDLES, HIGH_RISK_KEYWORDS, MEDIUM_RISK_KEYWORDS


class IntelligenceExtractor:
    """
    Comprehensive intelligence extractor with obfuscation handling.
    """

    # ── Compiled regex patterns (compiled once at import) ──

    # Indian phone numbers: +91, 91, 0 prefix optional, 10 digits starting 6-9
    # Handles: 9876543210, 98765 43210, 9876-543-210, 987 654 3210, etc.
    # (?<!\d) ensures we don't match trailing digits of a longer number (e.g. bank account)
    _PHONE_INDIAN = re.compile(
        r'(?<!\d)(?:(?:\+91|91|0)[\s\-.]?)?([6-9](?:\d[\s\-.]?){8}\d)(?!\d)',
    )
    # Parenthesized: (98765) 43210
    _PHONE_PAREN = re.compile(
        r'\(([6-9]\d{4})\)\s*(\d{5})',
    )
    # International
    _PHONE_INTL = re.compile(
        r'\+(?!91)(\d{1,3})[\s\-]?(\d{7,14})',
    )

    # UPI IDs: standard
    _UPI_STANDARD = re.compile(
        r'\b([a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64})\b',
        re.IGNORECASE,
    )
    # UPI obfuscated: user AT paytm, user (at) paytm
    # Only match explicit markers like (at) or uppercase AT, not lowercase "at" (common English word)
    _UPI_OBFUSCATED = re.compile(
        r'\b([a-zA-Z0-9.\-_]{2,256})\s*(?:\(at\)|AT)\s*([a-zA-Z]{2,64})\b',
    )

    # Bank account numbers (9-18 digits with context)
    _BANK_ACCOUNT = re.compile(r'\b(\d{9,18})\b')
    # IFSC codes
    _IFSC = re.compile(r'\b([A-Z]{4}0[A-Z0-9]{6})\b', re.IGNORECASE)

    # URLs
    _URL = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
    _SHORT_URL = re.compile(
        r'\b(?:bit\.ly|goo\.gl|t\.co|tinyurl\.com|is\.gd|buff\.ly|ow\.ly|rebrand\.ly|cutt\.ly|shorturl\.at)/[a-zA-Z0-9]+\b',
        re.IGNORECASE,
    )
    # Obfuscated URLs: example[dot]com, example . com/path
    _URL_OBFUSCATED = re.compile(
        r'\b([a-zA-Z0-9\-]+)\s*[\[\(]?\s*(?:dot|\.)\s*[\]\)]?\s*([a-zA-Z]{2,10})(?:/[^\s]*)?',
        re.IGNORECASE,
    )

    # Email
    _EMAIL = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
    _EMAIL_OBFUSCATED = re.compile(
        r'\b([A-Za-z0-9._%+\-]+)\s*(?:\(at\)|AT)\s*([A-Za-z0-9.\-]+)\s*(?:\(dot\)|DOT)\s*([A-Za-z]{2,})\b',
        re.IGNORECASE,
    )

    # Case/Reference IDs: CASE-12345, REF-12345, case no. 12345, complaint ID ABC123, etc.
    _CASE_ID = re.compile(
        r'(?:case|ref|reference|complaint|ticket|incident|file)\s*(?:no\.?|number|id|#|:)\s*[:.]?\s*([A-Za-z0-9\-/]{3,30})',
        re.IGNORECASE,
    )
    _CASE_ID_PREFIX = re.compile(
        r'\b((?:CASE|REF|CRN|TKT|INC|FIR|CR|SR|COMP|FILE)[- /#]?[A-Z0-9\-]{3,20})\b',
    )

    # Policy Numbers: policy no. 12345, POL-12345, policy number ABC123
    _POLICY_NUMBER = re.compile(
        r'(?:policy|insurance)\s*(?:no\.?|number|id|#|:)\s*[:.]?\s*([A-Za-z0-9\-/]{3,30})',
        re.IGNORECASE,
    )
    _POLICY_PREFIX = re.compile(
        r'\b((?:POL|INS|LIC|POLICY)[- /#]?[A-Z0-9\-]{3,20})\b',
    )

    # Order Numbers: order ID 12345, ORD-12345, order number ABC123
    _ORDER_NUMBER = re.compile(
        r'(?:order|transaction|txn|invoice|bill)\s*(?:no\.?|number|id|#|:)\s*[:.]?\s*([A-Za-z0-9\-/]{3,30})',
        re.IGNORECASE,
    )
    _ORDER_PREFIX = re.compile(
        r'\b((?:ORD|TXN|INV|BILL|ORDER)[- /#]?[A-Z0-9\-]{3,20})\b',
    )

    # Money amounts
    _MONEY = re.compile(
        r'(?:₹|rs\.?|inr|rupees?)\s*([\d,]+(?:\.\d{1,2})?)',
        re.IGNORECASE,
    )
    _MONEY_REVERSE = re.compile(
        r'([\d,]+(?:\.\d{1,2})?)\s*(?:₹|rs\.?|inr|rupees?)',
        re.IGNORECASE,
    )

    # Suspicious TLDs
    _SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", ".link", ".info"}

    # Context words for bank account detection
    _BANK_CONTEXT = [
        "account", "a/c", "acc", "bank", "savings", "current",
        "deposit", "transfer", "ifsc", "branch", "neft", "rtgs", "imps",
    ]

    # Known UPI handles
    _UPI_HANDLES = set(UPI_HANDLES)

    def __init__(self):
        self._all_keywords = set(
            k.lower() for k in HIGH_RISK_KEYWORDS + MEDIUM_RISK_KEYWORDS
        )
        logger.info("IntelligenceExtractor initialized (enhanced)")

    def extract(self, message: str) -> IntelligenceData:
        """Extract all intelligence from a message."""
        if not message or not message.strip():
            return IntelligenceData()

        intel = IntelligenceData()
        intel.phoneNumbers = self._extract_phones(message)
        intel.upiIds = self._extract_upi(message)
        intel.bankAccounts = self._extract_bank_accounts(message)
        intel.phishingLinks = self._extract_links(message)
        intel.emailAddresses = self.get_emails(message)
        intel.caseIds = self._extract_case_ids(message)
        intel.policyNumbers = self._extract_policy_numbers(message)
        intel.orderNumbers = self._extract_order_numbers(message)
        intel.suspiciousKeywords = self._extract_keywords(message)

        total = intel.total_items()
        if total > 0:
            logger.info(
                f"Extracted: {len(intel.phoneNumbers)} phones, "
                f"{len(intel.upiIds)} UPIs, {len(intel.bankAccounts)} accounts, "
                f"{len(intel.phishingLinks)} links, {len(intel.suspiciousKeywords)} keywords"
            )
        return intel

    # ── Phone extraction ──

    def _extract_phones(self, message: str) -> List[str]:
        phones = set()

        # Standard Indian numbers (handles spaces/dashes in number)
        for m in self._PHONE_INDIAN.finditer(message):
            raw = m.group(1)
            digits = re.sub(r'[\s\-.]', '', raw)
            if self._valid_indian_phone(digits):
                phones.add(digits)

        # Parenthesized
        for m in self._PHONE_PAREN.finditer(message):
            digits = m.group(1) + m.group(2)
            if self._valid_indian_phone(digits):
                phones.add(digits)

        # International
        for m in self._PHONE_INTL.finditer(message):
            phones.add(f"+{m.group(1)}{m.group(2)}")

        return list(phones)

    @staticmethod
    def _valid_indian_phone(number: str) -> bool:
        if len(number) != 10:
            return False
        if number[0] not in "6789":
            return False
        if len(set(number)) == 1:
            return False
        return True

    # ── UPI extraction ──

    def _extract_upi(self, message: str) -> List[str]:
        upi_ids = set()

        # Standard
        for m in self._UPI_STANDARD.finditer(message):
            uid = m.group(1).lower()
            # Check if this is actually part of an email (followed by .tld or -subdomain with letters)
            end_pos = m.end()
            if end_pos < len(message) and message[end_pos] in '.-':
                # Check if followed by more domain chars (letter after . or -)
                rest = message[end_pos:]
                if re.match(r'[.\-][a-zA-Z]', rest):
                    continue  # likely an email domain, skip
            if self._valid_upi(uid):
                upi_ids.add(uid)

        # Obfuscated (AT / (at))
        for m in self._UPI_OBFUSCATED.finditer(message):
            uid = f"{m.group(1).lower()}@{m.group(2).lower()}"
            end_pos = m.end()
            if end_pos < len(message) and message[end_pos] in '.-':
                rest = message[end_pos:]
                if re.match(r'[.\-][a-zA-Z]', rest):
                    continue
            if self._valid_upi(uid):
                upi_ids.add(uid)

        return list(upi_ids)

    def _valid_upi(self, upi_id: str) -> bool:
        if "@" not in upi_id:
            return False
        username, handle = upi_id.rsplit("@", 1)
        if len(username) < 2:
            return False
        handle_lower = handle.lower()
        # Exclude obvious emails (domains with dots like gmail.com)
        if "." in handle_lower:
            return False
        # Check against known handles
        for vh in self._UPI_HANDLES:
            if vh in handle_lower:
                return True
        # Bank-like or payment-related suffix
        bank_parts = ["bank", "axis", "hdfc", "icici", "sbi", "pnb", "bob", "canara", "kotak",
                       "pay", "wallet", "cash", "money", "fin", "upi"]
        if any(bp in handle_lower for bp in bank_parts):
            return True
        # Accept any short handle without dots (likely UPI, not email)
        if len(handle_lower) <= 20:
            return True
        return False

    # ── Bank account extraction ──

    def _extract_bank_accounts(self, message: str) -> List[str]:
        accounts = set()
        msg_lower = message.lower()
        has_context = any(w in msg_lower for w in self._BANK_CONTEXT)

        for m in self._BANK_ACCOUNT.finditer(message):
            num = m.group(1)
            if has_context and self._likely_bank_account(num, message, m.start()):
                accounts.add(num)

        # IFSC codes — add as separate intelligence
        for m in self._IFSC.finditer(message):
            accounts.add(f"IFSC:{m.group(1).upper()}")

        return list(accounts)

    @staticmethod
    def _likely_bank_account(number: str, message: str, pos: int) -> bool:
        # Exclude phone numbers
        if len(number) == 10 and number[0] in "6789":
            return False
        if len(number) > 18:
            return False
        # 11-16 digits = typical Indian bank account
        if 11 <= len(number) <= 16:
            return True
        # Check surrounding context
        ctx = message[max(0, pos - 60):pos].lower()
        return any(w in ctx for w in [
            "account", "a/c", "acc", "bank", "ifsc", "transfer", "neft", "rtgs",
        ])

    # ── Link extraction ──

    def _extract_links(self, message: str) -> List[str]:
        links = set()
        # Collect positions already covered by emails or standard URLs
        covered_positions = set()
        for m in self._EMAIL.finditer(message):
            for i in range(m.start(), m.end()):
                covered_positions.add(i)

        for m in self._URL.finditer(message):
            url = m.group(0).rstrip(".,;:!?)")
            links.add(url)
            for i in range(m.start(), m.end()):
                covered_positions.add(i)

        for m in self._SHORT_URL.finditer(message):
            links.add(m.group(0))
            for i in range(m.start(), m.end()):
                covered_positions.add(i)

        # Obfuscated: example[dot]com
        for m in self._URL_OBFUSCATED.finditer(message):
            # Skip if this overlaps with an already-matched pattern
            if any(i in covered_positions for i in range(m.start(), m.end())):
                continue
            full = m.group(0)
            tld = m.group(2).lower()
            if tld in ("com", "in", "org", "net", "co", "io", "xyz", "tk", "ml", "info", "link"):
                reconstructed = f"{m.group(1)}.{tld}"
                if "/" in full:
                    path = full.split("/", 1)[-1] if "/" in full else ""
                    reconstructed += f"/{path}" if path else ""
                links.add(reconstructed)

        return list(links)

    # ── Email extraction ──

    def get_emails(self, message: str) -> List[str]:
        emails = set()
        for m in self._EMAIL.finditer(message):
            emails.add(m.group(0).lower())
        for m in self._EMAIL_OBFUSCATED.finditer(message):
            emails.add(f"{m.group(1)}@{m.group(2)}.{m.group(3)}".lower())
        return list(emails)

    # ── Money extraction ──

    def get_amounts(self, message: str) -> List[str]:
        amounts = set()
        for m in self._MONEY.finditer(message):
            amounts.add(m.group(1).replace(",", ""))
        for m in self._MONEY_REVERSE.finditer(message):
            amounts.add(m.group(1).replace(",", ""))
        return list(amounts)

    # ── Case ID extraction ──

    def _extract_case_ids(self, message: str) -> List[str]:
        ids = set()
        for m in self._CASE_ID.finditer(message):
            val = m.group(1).strip().strip(':.')
            if len(val) >= 3:
                ids.add(val)
        for m in self._CASE_ID_PREFIX.finditer(message):
            ids.add(m.group(1))
        return list(ids)

    # ── Policy number extraction ──

    def _extract_policy_numbers(self, message: str) -> List[str]:
        nums = set()
        for m in self._POLICY_NUMBER.finditer(message):
            val = m.group(1).strip().strip(':.')
            if len(val) >= 3:
                nums.add(val)
        for m in self._POLICY_PREFIX.finditer(message):
            nums.add(m.group(1))
        return list(nums)

    # ── Order number extraction ──

    def _extract_order_numbers(self, message: str) -> List[str]:
        nums = set()
        for m in self._ORDER_NUMBER.finditer(message):
            val = m.group(1).strip().strip(':.')
            if len(val) >= 3:
                nums.add(val)
        for m in self._ORDER_PREFIX.finditer(message):
            nums.add(m.group(1))
        return list(nums)

    # ── Keyword extraction ──

    def _extract_keywords(self, message: str) -> List[str]:
        msg_lower = message.lower()
        return [kw for kw in self._all_keywords if kw in msg_lower]

    # ── IFSC ──

    def get_ifsc_codes(self, message: str) -> List[str]:
        return [m.group(1).upper() for m in self._IFSC.finditer(message)]

    # ── Batch extraction from conversation ──

    def extract_from_history(self, history: List[Dict]) -> IntelligenceData:
        combined = IntelligenceData()
        for msg in history:
            sender = msg.get("sender", "").lower()
            # Extract from scammer messages (any non-user sender)
            if sender != "user":
                text = msg.get("text", "")
                if text:
                    combined.merge(self.extract(text))
        return combined


# Singleton
intelligence_extractor = IntelligenceExtractor()


def extract_intelligence(message: str) -> IntelligenceData:
    """Extract intelligence from a single message."""
    return intelligence_extractor.extract(message)


def extract_from_conversation(history: List[Dict]) -> IntelligenceData:
    """Extract intelligence from conversation history."""
    return intelligence_extractor.extract_from_history(history)
