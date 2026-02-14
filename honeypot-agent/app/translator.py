"""
Translation module for Hindi/Devanagari support.
Detects Hindi text, translates to English for processing, and translates replies back.
Uses deep-translator (Google Translate wrapper) — no httpx conflicts.
"""

import re
from typing import Tuple

from .config import logger

try:
    from deep_translator import GoogleTranslator
    _TRANSLATOR_AVAILABLE = True
except Exception:
    _TRANSLATOR_AVAILABLE = False
    logger.warning("deep-translator not available, Hindi translation disabled")

# Devanagari Unicode range
_DEVANAGARI_PATTERN = re.compile(r'[\u0900-\u097F]')


def is_hindi(text: str) -> bool:
    """Check if text contains Devanagari script characters."""
    return bool(_DEVANAGARI_PATTERN.search(text))


def translate_to_english(text: str) -> Tuple[str, bool]:
    """Translate Hindi text to English. Returns (translated_text, success)."""
    if not _TRANSLATOR_AVAILABLE:
        return text, False
    try:
        result = GoogleTranslator(source='hi', target='en').translate(text)
        return result, True
    except Exception as e:
        logger.error(f"Translation to English failed: {e}")
        return text, False


def translate_to_hindi(text: str) -> Tuple[str, bool]:
    """Translate English text to Hindi. Returns (translated_text, success)."""
    if not _TRANSLATOR_AVAILABLE:
        return text, False
    try:
        result = GoogleTranslator(source='en', target='hi').translate(text)
        return result, True
    except Exception as e:
        logger.error(f"Translation to Hindi failed: {e}")
        return text, False


def detect_and_translate(text: str) -> Tuple[str, str, bool]:
    """
    Detect if text is Hindi and translate to English if so.
    Returns (english_text, detected_language, was_translated).
    """
    if is_hindi(text):
        translated, success = translate_to_english(text)
        if success:
            return translated, "hi", True
        return text, "hi", False
    return text, "en", False


def translate_response(text: str, target_lang: str) -> str:
    """Translate response back to target language if needed."""
    if target_lang == "hi":
        translated, success = translate_to_hindi(text)
        if success:
            return translated
    return text
