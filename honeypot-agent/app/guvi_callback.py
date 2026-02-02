"""
GUVI Callback Module for the Honeypot System.
Sends final results to the GUVI hackathon platform.
"""

import time
import asyncio
import requests
from typing import Dict, Optional, Any
from concurrent.futures import ThreadPoolExecutor
from .models import GuviCallbackPayload, SessionData
from .config import logger, settings


class GuviCallback:
    """
    Handles callbacks to the GUVI hackathon platform.
    Sends extracted intelligence and session results.
    """

    def __init__(self):
        """Initialize the callback handler."""
        self.callback_url = settings.GUVI_CALLBACK_URL
        self.max_retries = settings.MAX_RETRIES
        self.retry_delay = settings.RETRY_DELAY_SECONDS
        self._executor = ThreadPoolExecutor(max_workers=5)
        logger.info(f"GuviCallback initialized with URL: {self.callback_url}")

    def _prepare_payload(self, session_data: Dict) -> GuviCallbackPayload:
        """
        Prepare the callback payload from session data.

        Args:
            session_data: Dictionary containing session information

        Returns:
            GuviCallbackPayload object
        """
        # Ensure intelligence is in correct format
        intelligence = session_data.get("extractedIntelligence", {})
        if hasattr(intelligence, "to_dict"):
            intelligence = intelligence.to_dict()

        # Ensure all required fields in intelligence
        formatted_intelligence = {
            "bankAccounts": intelligence.get("bankAccounts", []),
            "upiIds": intelligence.get("upiIds", []),
            "phishingLinks": intelligence.get("phishingLinks", []),
            "phoneNumbers": intelligence.get("phoneNumbers", []),
            "suspiciousKeywords": intelligence.get("suspiciousKeywords", [])
        }

        return GuviCallbackPayload(
            sessionId=session_data.get("sessionId", ""),
            scamDetected=session_data.get("scamDetected", False),
            totalMessagesExchanged=session_data.get("totalMessagesExchanged", 0),
            extractedIntelligence=formatted_intelligence,
            agentNotes=session_data.get("agentNotes", "")
        )

    def send_result(self, session_data: Dict) -> bool:
        """
        Send final result to GUVI platform (synchronous).

        Args:
            session_data: Session data to send

        Returns:
            True if successful, False otherwise
        """
        try:
            payload = self._prepare_payload(session_data)
            return self._send_with_retry(payload)
        except Exception as e:
            logger.error(f"Error preparing callback payload: {e}")
            return False

    def send_result_async(self, session_data: Dict) -> None:
        """
        Send final result asynchronously (non-blocking).

        Args:
            session_data: Session data to send
        """
        self._executor.submit(self._async_send_wrapper, session_data)
        logger.info(f"Queued async callback for session: {session_data.get('sessionId')}")

    def _async_send_wrapper(self, session_data: Dict) -> None:
        """Wrapper for async sending."""
        try:
            success = self.send_result(session_data)
            if success:
                logger.info(
                    f"Async callback successful for session: {session_data.get('sessionId')}"
                )
            else:
                logger.warning(
                    f"Async callback failed for session: {session_data.get('sessionId')}"
                )
        except Exception as e:
            logger.error(f"Error in async callback: {e}")

    def _send_with_retry(self, payload: GuviCallbackPayload) -> bool:
        """
        Send callback with retry logic.

        Args:
            payload: Callback payload to send

        Returns:
            True if successful
        """
        payload_dict = payload.model_dump()

        for attempt in range(self.max_retries):
            try:
                logger.info(
                    f"Sending callback attempt {attempt + 1}/{self.max_retries} "
                    f"for session: {payload.sessionId}"
                )

                response = requests.post(
                    self.callback_url,
                    json=payload_dict,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "HoneypotAgent/1.0"
                    },
                    timeout=30
                )

                if response.status_code in [200, 201, 202]:
                    logger.info(
                        f"Callback successful for session {payload.sessionId}: "
                        f"status={response.status_code}"
                    )
                    return True
                else:
                    logger.warning(
                        f"Callback returned status {response.status_code}: "
                        f"{response.text[:200]}"
                    )

            except requests.exceptions.Timeout:
                logger.warning(f"Callback timeout on attempt {attempt + 1}")
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Callback connection error on attempt {attempt + 1}: {e}")
            except requests.exceptions.RequestException as e:
                logger.error(f"Callback request error: {e}")

            # Wait before retry (exponential backoff)
            if attempt < self.max_retries - 1:
                wait_time = self.retry_delay * (2 ** attempt)
                logger.info(f"Waiting {wait_time}s before retry...")
                time.sleep(wait_time)

        logger.error(f"All callback attempts failed for session: {payload.sessionId}")
        return False

    def send_from_session(self, session: SessionData) -> bool:
        """
        Send callback directly from SessionData object.

        Args:
            session: SessionData object

        Returns:
            True if successful
        """
        session_data = {
            "sessionId": session.sessionId,
            "scamDetected": session.scamDetected,
            "totalMessagesExchanged": session.messageCount,
            "extractedIntelligence": session.extractedIntelligence.to_dict(),
            "agentNotes": session.agentNotes
        }
        return self.send_result(session_data)

    def send_from_session_async(self, session: SessionData) -> None:
        """
        Send callback asynchronously from SessionData object.

        Args:
            session: SessionData object
        """
        session_data = {
            "sessionId": session.sessionId,
            "scamDetected": session.scamDetected,
            "totalMessagesExchanged": session.messageCount,
            "extractedIntelligence": session.extractedIntelligence.to_dict(),
            "agentNotes": session.agentNotes
        }
        self.send_result_async(session_data)

    def test_connection(self) -> Dict[str, Any]:
        """
        Test connection to GUVI callback endpoint.

        Returns:
            Dictionary with test results
        """
        try:
            # Just check if the endpoint is reachable
            response = requests.options(
                self.callback_url,
                timeout=10
            )
            return {
                "reachable": True,
                "status_code": response.status_code,
                "url": self.callback_url
            }
        except requests.exceptions.RequestException as e:
            return {
                "reachable": False,
                "error": str(e),
                "url": self.callback_url
            }


# Singleton instance
guvi_callback = GuviCallback()


def send_final_result(session_data: Dict) -> bool:
    """
    Convenience function to send final result to GUVI.

    Args:
        session_data: Session data dictionary

    Returns:
        True if successful
    """
    return guvi_callback.send_result(session_data)


def send_final_result_async(session_data: Dict) -> None:
    """
    Convenience function to send final result asynchronously.

    Args:
        session_data: Session data dictionary
    """
    guvi_callback.send_result_async(session_data)


def send_session_result(session: SessionData) -> bool:
    """
    Convenience function to send SessionData result.

    Args:
        session: SessionData object

    Returns:
        True if successful
    """
    return guvi_callback.send_from_session(session)


def send_session_result_async(session: SessionData) -> None:
    """
    Convenience function to send SessionData result asynchronously.

    Args:
        session: SessionData object
    """
    guvi_callback.send_from_session_async(session)
