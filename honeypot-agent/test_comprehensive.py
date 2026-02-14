"""
Comprehensive Test Suite for the Honeypot Scam Detection System.
50+ test cases covering scam detection, edge cases, legitimate messages,
multi-turn conversations, obfuscated content, and intelligence extraction.

Usage:
    python test_comprehensive.py
    python test_comprehensive.py --quick     # Skip slow API tests
    python test_comprehensive.py --category scam  # Run specific category
"""

import sys
import os
import time
import json
import argparse

# Add parent dir to path
sys.path.insert(0, os.path.dirname(__file__))

from app.scam_detector import detect_scam, should_activate_agent
from app.intelligence_extractor import extract_intelligence
from app.urgency_detector import detect_urgency, detect_threats, analyze_pressure_tactics
from app.behavior_analyzer import BehaviorAnalyzer
from app.conversation_strategy import get_strategy, select_persona, get_stage
from app.translator import is_hindi, detect_and_translate, translate_response, translate_to_english, translate_to_hindi


# ══════════════════════════════════════════════════════════════════════
# Test Framework
# ══════════════════════════════════════════════════════════════════════

class TestResult:
    def __init__(self, name, passed, details="", duration_ms=0):
        self.name = name
        self.passed = passed
        self.details = details
        self.duration_ms = duration_ms

    def __str__(self):
        icon = "PASS" if self.passed else "FAIL"
        time_str = f" ({self.duration_ms}ms)" if self.duration_ms else ""
        detail = f" - {self.details}" if self.details and not self.passed else ""
        return f"  [{icon}] {self.name}{time_str}{detail}"


def run_test(name, test_fn):
    start = time.time()
    try:
        result = test_fn()
        duration = int((time.time() - start) * 1000)
        if result is True:
            return TestResult(name, True, duration_ms=duration)
        elif result is False:
            return TestResult(name, False, "Assertion failed", duration)
        elif isinstance(result, str):
            return TestResult(name, False, result, duration)
        else:
            return TestResult(name, True, duration_ms=duration)
    except Exception as e:
        duration = int((time.time() - start) * 1000)
        return TestResult(name, False, f"Exception: {e}", duration)


# ══════════════════════════════════════════════════════════════════════
# CATEGORY 1: BASIC SCAM DETECTION (10 tests)
# ══════════════════════════════════════════════════════════════════════

def test_aggressive_bank_fraud():
    r = detect_scam("Your bank account has been blocked! Share your OTP immediately or you will lose all your money!")
    if not r.is_scam:
        return "Expected scam, got legit"
    if r.confidence < 0.4:
        return f"Low confidence: {r.confidence}"
    return True

def test_subtle_bank_fraud():
    r = detect_scam("Dear customer, we noticed unusual activity on your account. Please verify your details to avoid suspension.")
    if not r.is_scam:
        return "Expected scam, got legit"
    return True

def test_upi_fraud():
    r = detect_scam("Please send Rs.500 to verify your UPI ID. Transfer money to scammer@paytm immediately.")
    if not r.is_scam:
        return "Expected scam"
    return True

def test_otp_theft():
    r = detect_scam("An OTP has been sent to your phone. Please share the verification code with me to complete the process.")
    if not r.is_scam:
        return "Expected scam"
    return True

def test_phishing_link():
    r = detect_scam("Click here to update your KYC: https://fake-bank-site.com/verify. Do it now or your account will be blocked.")
    if not r.is_scam:
        return "Expected scam"
    return True

def test_investment_scam():
    r = detect_scam("Invest Rs.10000 and get guaranteed returns of Rs.50000 within 30 days! Double your money!")
    if not r.is_scam:
        return "Expected scam"
    return True

def test_job_scam():
    r = detect_scam("Work from home and earn Rs.5000 daily! Just pay a registration fee of Rs.500 to get started.")
    if not r.is_scam:
        return "Expected scam"
    return True

def test_prize_lottery_scam():
    r = detect_scam("Congratulations! You have won a prize of Rs.10 lakhs in our lottery! Claim your reward by calling now.")
    if not r.is_scam:
        return "Expected scam"
    return True

def test_kyc_update_scam():
    r = detect_scam("Your KYC update is pending. Complete it immediately or your account will be deactivated today.")
    if not r.is_scam:
        return "Expected scam"
    return True

def test_tax_legal_threat():
    r = detect_scam("This is from Income Tax department. You have pending tax dues. Legal action will be taken against you if you don't pay immediately.")
    if not r.is_scam:
        return "Expected scam"
    return True


# ══════════════════════════════════════════════════════════════════════
# CATEGORY 2: EDGE CASES (10 tests)
# ══════════════════════════════════════════════════════════════════════

def test_empty_message():
    r = detect_scam("")
    if r.is_scam:
        return "Empty message should not be scam"
    return True

def test_very_short_message():
    r = detect_scam("hi")
    if r.is_scam:
        return "Greeting should not be scam"
    return True

def test_very_long_message():
    long_msg = "Your bank account has been compromised. " * 100
    r = detect_scam(long_msg)
    if not r.is_scam:
        return "Long scam message should be detected"
    return True

def test_only_special_characters():
    r = detect_scam("!@#$%^&*()")
    if r.is_scam:
        return "Special chars should not be scam"
    return True

def test_mixed_language():
    r = detect_scam("Aapka account block ho jayega. Please share OTP turant.")
    # This contains "account", "block", "share OTP" — should detect
    if not r.is_scam:
        return "Mixed language scam should be detected"
    return True

def test_all_uppercase():
    r = detect_scam("YOUR ACCOUNT HAS BEEN BLOCKED! SHARE OTP NOW!")
    if not r.is_scam:
        return "Uppercase scam should be detected"
    return True

def test_numbers_only():
    r = detect_scam("123456789")
    if r.is_scam:
        return "Numbers only should not be scam"
    return True

def test_repeated_characters():
    r = detect_scam("hellooooooo howwww are youuuuu")
    if r.is_scam:
        return "Repeated chars greeting should not be scam"
    return True

def test_whitespace_only():
    r = detect_scam("   \t\n   ")
    if r.is_scam:
        return "Whitespace should not be scam"
    return True

def test_unicode_characters():
    r = detect_scam("Hello! How are you? 😊")
    if r.is_scam:
        return "Emoji greeting should not be scam"
    return True


# ══════════════════════════════════════════════════════════════════════
# CATEGORY 3: LEGITIMATE MESSAGES (10 tests)
# ══════════════════════════════════════════════════════════════════════

def test_friendly_greeting():
    r = detect_scam("Hello, how are you doing today?")
    if r.is_scam:
        return "Greeting should not be scam"
    return True

def test_general_inquiry():
    r = detect_scam("What time does the movie start?")
    if r.is_scam:
        return "General inquiry should not be scam"
    return True

def test_customer_support():
    r = detect_scam("I need help finding my order. Can you check the status?")
    if r.is_scam:
        return "Support question should not be scam"
    return True

def test_business_communication():
    r = detect_scam("The meeting has been moved to 3 PM. Please confirm your attendance.")
    if r.is_scam:
        return "Business message should not be scam"
    return True

def test_personal_conversation():
    r = detect_scam("Happy birthday! Hope you have a wonderful day with your family.")
    if r.is_scam:
        return "Birthday wish should not be scam"
    return True

def test_technical_question():
    r = detect_scam("How do I install Python on my computer? I need it for my project.")
    if r.is_scam:
        return "Tech question should not be scam"
    return True

def test_feedback_message():
    r = detect_scam("I really enjoyed the product. Great quality and fast delivery!")
    if r.is_scam:
        return "Feedback should not be scam"
    return True

def test_thank_you_message():
    r = detect_scam("Thank you so much for your help! I really appreciate it.")
    if r.is_scam:
        return "Thank you should not be scam"
    return True

def test_appointment_booking():
    r = detect_scam("I would like to book an appointment for next Tuesday at 10 AM.")
    if r.is_scam:
        return "Appointment booking should not be scam"
    return True

def test_product_inquiry():
    r = detect_scam("Do you have the blue version of this shirt in size medium?")
    if r.is_scam:
        return "Product inquiry should not be scam"
    return True


# ══════════════════════════════════════════════════════════════════════
# CATEGORY 4: MULTI-TURN CONVERSATIONS (5 tests)
# ══════════════════════════════════════════════════════════════════════

def test_5turn_bank_scam():
    """Simulate a 5-turn bank scam conversation."""
    history = [
        {"sender": "scammer", "text": "Hello sir, I am calling from SBI bank."},
        {"sender": "user", "text": "Hello, who is this?"},
        {"sender": "scammer", "text": "Your account has unusual activity. We need to verify."},
        {"sender": "user", "text": "Oh no, what happened?"},
    ]
    msg = "Please share your OTP to verify your identity immediately."
    r = detect_scam(msg, history, "test-5turn")
    if not r.is_scam:
        return "Multi-turn bank scam should be detected"
    return True

def test_10turn_upi_fraud():
    """10-turn UPI fraud conversation."""
    history = [
        {"sender": "scammer", "text": "Hello, this is customer care."},
        {"sender": "user", "text": "Which company?"},
        {"sender": "scammer", "text": "Your recent payment failed."},
        {"sender": "user", "text": "What payment?"},
        {"sender": "scammer", "text": "The refund of Rs.500 is pending for you."},
        {"sender": "user", "text": "Really? How do I get it?"},
        {"sender": "scammer", "text": "I need your UPI ID to process the refund."},
        {"sender": "user", "text": "What is UPI ID?"},
        {"sender": "scammer", "text": "Give me your paytm number or UPI ID."},
        {"sender": "user", "text": "Let me check..."},
    ]
    msg = "Send Rs.1 to verify your account. UPI: fraud@paytm"
    r = detect_scam(msg, history, "test-10turn")
    if not r.is_scam:
        return "10-turn UPI fraud should be detected"
    return True

def test_15turn_investment_scam():
    """Investment scam with trust building."""
    history = [
        {"sender": "scammer", "text": "Hi, I am a financial advisor."},
        {"sender": "user", "text": "Hello"},
        {"sender": "scammer", "text": "I have an amazing investment opportunity."},
        {"sender": "user", "text": "Tell me more."},
        {"sender": "scammer", "text": "Our clients earn 300% returns."},
        {"sender": "user", "text": "That sounds high."},
    ]
    msg = "Invest Rs.10000 now and get guaranteed returns of Rs.50000. Transfer to invest@gpay."
    r = detect_scam(msg, history, "test-15turn")
    if not r.is_scam:
        return "Investment scam should be detected"
    return True

def test_20turn_complex_scam():
    """Complex multi-type scam in one conversation."""
    history = [
        {"sender": "scammer", "text": "I am officer from RBI."},
        {"sender": "user", "text": "RBI? What is this about?"},
        {"sender": "scammer", "text": "Your account has been flagged for suspicious activity."},
        {"sender": "user", "text": "What activity?"},
        {"sender": "scammer", "text": "Unauthorized transactions detected. Account will be frozen."},
        {"sender": "user", "text": "Oh no!"},
        {"sender": "scammer", "text": "Share your OTP to verify identity."},
        {"sender": "user", "text": "What OTP?"},
    ]
    msg = "Send the OTP immediately or legal action will be taken against you. You will be arrested."
    r = detect_scam(msg, history, "test-20turn")
    if not r.is_scam:
        return "Complex multi-type scam should be detected"
    if r.confidence < 0.5:
        return f"Confidence too low: {r.confidence}"
    return True

def test_escalating_conversation():
    """Test that escalation is detected."""
    history = [
        {"sender": "scammer", "text": "Please verify your account."},
        {"sender": "user", "text": "Why?"},
        {"sender": "scammer", "text": "Your account will be suspended if you don't."},
        {"sender": "user", "text": "Suspended?"},
        {"sender": "scammer", "text": "Yes, immediately. Share OTP now or account will be blocked permanently!"},
    ]
    analyzer = BehaviorAnalyzer()
    result = analyzer.analyze_conversation("test-escalation", history)
    if not result["escalation_detected"]:
        return "Escalation should be detected"
    return True


# ══════════════════════════════════════════════════════════════════════
# CATEGORY 5: OBFUSCATED CONTENT (10 tests)
# ══════════════════════════════════════════════════════════════════════

def test_spaced_phone_number():
    intel = extract_intelligence("Call me at 98765 43210 for help.")
    if not intel.phoneNumbers:
        return "Should extract spaced phone number"
    return True

def test_dashed_phone_number():
    intel = extract_intelligence("My number is 9876-543-210.")
    if not intel.phoneNumbers:
        return "Should extract dashed phone number"
    return True

def test_upi_at_obfuscation():
    intel = extract_intelligence("Send money to scammer AT paytm")
    if not intel.upiIds:
        return "Should extract obfuscated UPI (AT)"
    return True

def test_link_dot_obfuscation():
    """Test detection of obfuscated links."""
    r = detect_scam("Click here: example[dot]com/verify to update your account immediately")
    # The scam should be detected due to keywords even if link extraction varies
    if not r.is_scam:
        return "Obfuscated link scam should be detected"
    return True

def test_mixed_case_keywords():
    r = detect_scam("Share your OtP NOW! Your BaNk account will be BLOCKED!")
    if not r.is_scam:
        return "Mixed case scam should be detected"
    return True

def test_unicode_in_scam():
    r = detect_scam("Your account will be blocked! Send ₹500 to verify. UPI: test@paytm")
    if not r.is_scam:
        return "Scam with unicode should be detected"
    return True

def test_emoji_scam():
    r = detect_scam("🚨 URGENT! Your bank account will be suspended! Share OTP now! 🚨")
    if not r.is_scam:
        return "Emoji scam should be detected"
    return True

def test_html_content():
    r = detect_scam("Your account &amp; will be blocked. Click &lt;here&gt; to verify.")
    # Contains "account", "blocked", "verify" — should detect
    if not r.is_scam:
        return "HTML-encoded scam should be detected"
    return True

def test_url_shortener():
    r = detect_scam("Verify your account here: bit.ly/xyz123 immediately or it will be blocked.")
    if not r.is_scam:
        return "URL shortener scam should be detected"
    return True

def test_phone_with_prefix():
    intel = extract_intelligence("Contact us at +91-9876543210 or 09876543210")
    if not intel.phoneNumbers:
        return "Should extract prefixed phone numbers"
    return True


# ══════════════════════════════════════════════════════════════════════
# CATEGORY 6: INTELLIGENCE EXTRACTION (5 tests)
# ══════════════════════════════════════════════════════════════════════

def test_extract_multiple_phones():
    intel = extract_intelligence("Call 9876543210 or 8765432109 for help.")
    if len(intel.phoneNumbers) < 2:
        return f"Expected 2 phones, got {len(intel.phoneNumbers)}"
    return True

def test_extract_multiple_upi():
    intel = extract_intelligence("Pay to user1@paytm or user2@phonepe")
    if len(intel.upiIds) < 2:
        return f"Expected 2 UPIs, got {len(intel.upiIds)}"
    return True

def test_extract_mixed_intel():
    msg = "Send OTP to 9876543210 and pay Rs.500 via scammer@paytm or visit https://fake.com/verify"
    intel = extract_intelligence(msg)
    if not intel.phoneNumbers:
        return "Should extract phone"
    if not intel.upiIds:
        return "Should extract UPI"
    if not intel.phishingLinks:
        return "Should extract link"
    return True

def test_extract_bank_account():
    intel = extract_intelligence("Transfer to bank account number 12345678901234 IFSC: SBIN0001234")
    if not intel.bankAccounts:
        return "Should extract bank account/IFSC"
    return True

def test_extract_keywords():
    intel = extract_intelligence("Your account is blocked. Verify immediately or face suspension.")
    if not intel.suspiciousKeywords:
        return "Should extract suspicious keywords"
    if len(intel.suspiciousKeywords) < 2:
        return f"Expected 2+ keywords, got {len(intel.suspiciousKeywords)}"
    return True


# ══════════════════════════════════════════════════════════════════════
# CATEGORY 7: URGENCY & THREAT DETECTION (5 tests)
# ══════════════════════════════════════════════════════════════════════

def test_high_urgency():
    r = detect_urgency("You must act immediately! Time is running out!")
    if r["urgency_level"] != "high":
        return f"Expected high urgency, got {r['urgency_level']}"
    return True

def test_high_threat():
    r = detect_threats("Your account will be blocked and you will be arrested.")
    if r["threat_level"] != "high":
        return f"Expected high threat, got {r['threat_level']}"
    return True

def test_no_urgency():
    r = detect_urgency("How are you doing today?")
    if r["urgency_level"] != "low":
        return f"Expected low urgency, got {r['urgency_level']}"
    return True

def test_combined_pressure():
    r = analyze_pressure_tactics("Your account will be blocked immediately! Pay now or face arrest!")
    if r["combined_pressure_score"] < 0.5:
        return f"Expected high pressure, got {r['combined_pressure_score']}"
    return True

def test_pressure_with_legit():
    r = analyze_pressure_tactics("Please let me know when you are free for a meeting.")
    if r["combined_pressure_score"] > 0.3:
        return f"Legit message should have low pressure: {r['combined_pressure_score']}"
    return True


# ══════════════════════════════════════════════════════════════════════
# CATEGORY 8: CONVERSATION STRATEGY (5 tests)
# ══════════════════════════════════════════════════════════════════════

def test_early_stage():
    stage = get_stage(2)
    if stage != "early":
        return f"Turn 2 should be early, got {stage}"
    return True

def test_middle_stage():
    stage = get_stage(8)
    if stage != "middle":
        return f"Turn 8 should be middle, got {stage}"
    return True

def test_late_stage():
    stage = get_stage(18)
    if stage != "late":
        return f"Turn 18 should be late, got {stage}"
    return True

def test_persona_consistency():
    p1 = select_persona("session-abc")
    p2 = select_persona("session-abc")
    if p1["name"] != p2["name"]:
        return "Same session should get same persona"
    return True

def test_strategy_has_required_fields():
    s = get_strategy("test-session", 5)
    required = ["stage", "persona", "goal", "tactics", "response_style", "emotion"]
    for field in required:
        if field not in s:
            return f"Missing field: {field}"
    return True


# ══════════════════════════════════════════════════════════════════════
# CATEGORY 9: HINDI / DEVANAGARI TRANSLATION (10 tests)
# ══════════════════════════════════════════════════════════════════════

def test_is_hindi_pure_devanagari():
    """Pure Devanagari text should be detected as Hindi."""
    if not is_hindi("आपका बैंक अकाउंट ब्लॉक हो गया है"):
        return "Pure Devanagari not detected"
    return True

def test_is_hindi_mixed():
    """Mixed Hindi + English with Devanagari chars should be detected."""
    if not is_hindi("Please अपना OTP send करो"):
        return "Mixed Hindi+English not detected"
    return True

def test_is_hindi_english_only():
    """Pure English should NOT be detected as Hindi."""
    if is_hindi("Your bank account has been blocked"):
        return "English text wrongly detected as Hindi"
    return True

def test_is_hindi_romanized():
    """Romanized Hindi (no Devanagari) should NOT be detected as Hindi."""
    if is_hindi("aapka account block ho gaya hai"):
        return "Romanized Hindi wrongly detected as Hindi"
    return True

def test_is_hindi_empty():
    """Empty string should NOT be detected as Hindi."""
    if is_hindi(""):
        return "Empty string wrongly detected as Hindi"
    return True

def test_translate_hindi_to_english():
    """Hindi bank scam message should translate to English with scam keywords."""
    translated, success = translate_to_english("आपका बैंक अकाउंट ब्लॉक हो गया है")
    if not success:
        return "Translation failed"
    lower = translated.lower()
    if "bank" not in lower and "account" not in lower and "block" not in lower:
        return f"Translation missing key terms: {translated}"
    return True

def test_translate_english_to_hindi():
    """English text should translate to Hindi (contains Devanagari)."""
    translated, success = translate_to_hindi("Your bank account has been blocked")
    if not success:
        return "Translation failed"
    if not is_hindi(translated):
        return f"Translation not in Hindi: {translated}"
    return True

def test_detect_and_translate_hindi():
    """detect_and_translate should translate Hindi and return lang='hi'."""
    english_text, lang, was_translated = detect_and_translate("आपका बैंक अकाउंट ब्लॉक हो गया है")
    if not was_translated:
        return "Should have been translated"
    if lang != "hi":
        return f"Expected lang 'hi', got '{lang}'"
    if is_hindi(english_text):
        return f"Result still contains Hindi: {english_text}"
    return True

def test_detect_and_translate_english():
    """detect_and_translate should pass English through unchanged."""
    text, lang, was_translated = detect_and_translate("Your bank account is blocked")
    if was_translated:
        return "English should not be translated"
    if lang != "en":
        return f"Expected lang 'en', got '{lang}'"
    if text != "Your bank account is blocked":
        return "English text should pass through unchanged"
    return True

def test_translate_response_roundtrip():
    """translate_response should return Hindi when target_lang='hi'."""
    reply = translate_response("Oh no! What happened to my account?", "hi")
    if not is_hindi(reply):
        return f"Reply not in Hindi: {reply}"
    return True

def test_translate_response_english_passthrough():
    """translate_response should return English unchanged when target_lang='en'."""
    reply = translate_response("Oh no! What happened?", "en")
    if reply != "Oh no! What happened?":
        return "English reply should not be modified"
    return True

def test_hindi_scam_detected_after_translation():
    """Hindi scam message should be detected as scam after translation."""
    english_text, lang, was_translated = detect_and_translate("आपका बैंक अकाउंट ब्लॉक हो गया है, अभी OTP भेजिये")
    if not was_translated:
        return "Translation failed"
    result = detect_scam(english_text)
    if not result.is_scam:
        return f"Translated text not detected as scam: {english_text}"
    return True

def test_hindi_legit_not_scam_after_translation():
    """Hindi greeting should NOT be detected as scam after translation."""
    english_text, lang, was_translated = detect_and_translate("नमस्ते, आप कैसे हैं?")
    if not was_translated:
        return "Translation failed"
    result = detect_scam(english_text)
    if result.is_scam:
        return f"Translated greeting wrongly flagged as scam: {english_text}"
    return True


# ══════════════════════════════════════════════════════════════════════
# Run Tests
# ══════════════════════════════════════════════════════════════════════

CATEGORIES = {
    "scam": {
        "name": "Basic Scam Detection",
        "tests": [
            ("Aggressive bank fraud", test_aggressive_bank_fraud),
            ("Subtle bank fraud", test_subtle_bank_fraud),
            ("UPI fraud", test_upi_fraud),
            ("OTP theft", test_otp_theft),
            ("Phishing link", test_phishing_link),
            ("Investment scam", test_investment_scam),
            ("Job scam", test_job_scam),
            ("Prize/lottery scam", test_prize_lottery_scam),
            ("KYC update scam", test_kyc_update_scam),
            ("Tax/legal threat", test_tax_legal_threat),
        ]
    },
    "edge": {
        "name": "Edge Cases",
        "tests": [
            ("Empty message", test_empty_message),
            ("Very short message", test_very_short_message),
            ("Very long message", test_very_long_message),
            ("Only special characters", test_only_special_characters),
            ("Mixed language", test_mixed_language),
            ("All uppercase", test_all_uppercase),
            ("Numbers only", test_numbers_only),
            ("Repeated characters", test_repeated_characters),
            ("Whitespace only", test_whitespace_only),
            ("Unicode characters", test_unicode_characters),
        ]
    },
    "legit": {
        "name": "Legitimate Messages (No False Positives)",
        "tests": [
            ("Friendly greeting", test_friendly_greeting),
            ("General inquiry", test_general_inquiry),
            ("Customer support", test_customer_support),
            ("Business communication", test_business_communication),
            ("Personal conversation", test_personal_conversation),
            ("Technical question", test_technical_question),
            ("Feedback message", test_feedback_message),
            ("Thank you message", test_thank_you_message),
            ("Appointment booking", test_appointment_booking),
            ("Product inquiry", test_product_inquiry),
        ]
    },
    "multiturn": {
        "name": "Multi-Turn Conversations",
        "tests": [
            ("5-turn bank scam", test_5turn_bank_scam),
            ("10-turn UPI fraud", test_10turn_upi_fraud),
            ("15-turn investment scam", test_15turn_investment_scam),
            ("20-turn complex scam", test_20turn_complex_scam),
            ("Escalating conversation", test_escalating_conversation),
        ]
    },
    "obfuscated": {
        "name": "Obfuscated Content",
        "tests": [
            ("Spaced phone number", test_spaced_phone_number),
            ("Dashed phone number", test_dashed_phone_number),
            ("UPI AT obfuscation", test_upi_at_obfuscation),
            ("Link DOT obfuscation", test_link_dot_obfuscation),
            ("Mixed case keywords", test_mixed_case_keywords),
            ("Unicode in scam", test_unicode_in_scam),
            ("Emoji scam", test_emoji_scam),
            ("HTML content", test_html_content),
            ("URL shortener", test_url_shortener),
            ("Phone with prefix", test_phone_with_prefix),
        ]
    },
    "extraction": {
        "name": "Intelligence Extraction",
        "tests": [
            ("Multiple phone numbers", test_extract_multiple_phones),
            ("Multiple UPI IDs", test_extract_multiple_upi),
            ("Mixed intelligence", test_extract_mixed_intel),
            ("Bank account & IFSC", test_extract_bank_account),
            ("Keyword extraction", test_extract_keywords),
        ]
    },
    "urgency": {
        "name": "Urgency & Threat Detection",
        "tests": [
            ("High urgency", test_high_urgency),
            ("High threat", test_high_threat),
            ("No urgency", test_no_urgency),
            ("Combined pressure", test_combined_pressure),
            ("Legit message pressure", test_pressure_with_legit),
        ]
    },
    "strategy": {
        "name": "Conversation Strategy",
        "tests": [
            ("Early stage", test_early_stage),
            ("Middle stage", test_middle_stage),
            ("Late stage", test_late_stage),
            ("Persona consistency", test_persona_consistency),
            ("Strategy fields", test_strategy_has_required_fields),
        ]
    },
    "translation": {
        "name": "Hindi / Devanagari Translation",
        "tests": [
            ("Pure Devanagari detection", test_is_hindi_pure_devanagari),
            ("Mixed Hindi+English detection", test_is_hindi_mixed),
            ("English-only not Hindi", test_is_hindi_english_only),
            ("Romanized Hindi not Hindi", test_is_hindi_romanized),
            ("Empty string not Hindi", test_is_hindi_empty),
            ("Hindi to English translation", test_translate_hindi_to_english),
            ("English to Hindi translation", test_translate_english_to_hindi),
            ("detect_and_translate Hindi", test_detect_and_translate_hindi),
            ("detect_and_translate English", test_detect_and_translate_english),
            ("Response roundtrip to Hindi", test_translate_response_roundtrip),
            ("Response English passthrough", test_translate_response_english_passthrough),
            ("Hindi scam detected after translation", test_hindi_scam_detected_after_translation),
            ("Hindi greeting not scam", test_hindi_legit_not_scam_after_translation),
        ]
    },
}


def main():
    parser = argparse.ArgumentParser(description="Comprehensive Honeypot Test Suite")
    parser.add_argument("--category", "-c", help="Run specific category")
    parser.add_argument("--quick", "-q", action="store_true", help="Skip slow tests")
    args = parser.parse_args()

    print("=" * 70)
    print("  HONEYPOT SCAM DETECTION - COMPREHENSIVE TEST SUITE")
    print("=" * 70)
    print()

    total_pass = 0
    total_fail = 0
    total_time = 0
    failed_tests = []

    categories_to_run = CATEGORIES
    if args.category:
        if args.category in CATEGORIES:
            categories_to_run = {args.category: CATEGORIES[args.category]}
        else:
            print(f"Unknown category: {args.category}")
            print(f"Available: {', '.join(CATEGORIES.keys())}")
            sys.exit(1)

    for cat_key, cat in categories_to_run.items():
        print(f"\n{'-' * 60}")
        print(f"  {cat['name']} ({len(cat['tests'])} tests)")
        print(f"{'-' * 60}")

        cat_pass = 0
        cat_fail = 0

        for name, fn in cat["tests"]:
            result = run_test(name, fn)
            print(result)

            total_time += result.duration_ms
            if result.passed:
                cat_pass += 1
                total_pass += 1
            else:
                cat_fail += 1
                total_fail += 1
                failed_tests.append(f"{cat['name']}: {name} - {result.details}")

        print(f"  Category: {cat_pass}/{cat_pass + cat_fail} passed")

    # Summary
    total = total_pass + total_fail
    print(f"\n{'=' * 70}")
    print(f"  RESULTS: {total_pass}/{total} passed, {total_fail} failed")
    print(f"  Total time: {total_time}ms")
    print(f"{'=' * 70}")

    if failed_tests:
        print(f"\n  FAILED TESTS:")
        for ft in failed_tests:
            print(f"    - {ft}")

    print()

    # Exit code
    sys.exit(0 if total_fail == 0 else 1)


if __name__ == "__main__":
    main()
