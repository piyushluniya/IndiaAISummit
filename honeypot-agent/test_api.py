#!/usr/bin/env python3
"""
Test Script for the Honeypot Scam Detection API.
Simulates GUVI platform requests to test all functionality.
"""

import os
import sys
import time
import json
import uuid
import requests
from datetime import datetime
from typing import Dict, List, Optional

# Configuration
BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
API_KEY = os.getenv("API_SECRET_KEY", "my-super-secret-honeypot-key-2026")

# Test session tracking
test_results = {
    "passed": 0,
    "failed": 0,
    "tests": []
}


def log_test(test_name: str, passed: bool, details: str = ""):
    """Log test result."""
    status = "PASSED" if passed else "FAILED"
    color = "\033[92m" if passed else "\033[91m"
    reset = "\033[0m"

    print(f"{color}[{status}]{reset} {test_name}")
    if details:
        print(f"         {details}")

    if passed:
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1

    test_results["tests"].append({
        "name": test_name,
        "passed": passed,
        "details": details
    })


def make_request(
    method: str,
    endpoint: str,
    data: Optional[Dict] = None,
    params: Optional[Dict] = None
) -> requests.Response:
    """Make an API request with authentication."""
    url = f"{BASE_URL}{endpoint}"
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY
    }

    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, params=params, timeout=30)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers, json=data, params=params, timeout=30)
        elif method.upper() == "DELETE":
            response = requests.delete(url, headers=headers, timeout=30)
        else:
            raise ValueError(f"Unsupported method: {method}")

        return response
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        raise


def create_message_payload(
    session_id: str,
    message_text: str,
    sender: str = "scammer",
    history: List[Dict] = None
) -> Dict:
    """Create a standard message payload for the /analyze endpoint."""
    return {
        "sessionId": session_id,
        "message": {
            "sender": sender,
            "text": message_text,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        },
        "conversationHistory": history or [],
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }


# ============================================================================
# Test Cases
# ============================================================================

def test_health_check():
    """Test the health check endpoint."""
    try:
        response = requests.get(f"{BASE_URL}/", timeout=10)
        passed = response.status_code == 200 and response.json().get("status") == "healthy"
        log_test("Health Check", passed, f"Status: {response.status_code}")
    except Exception as e:
        log_test("Health Check", False, str(e))


def test_authentication_missing():
    """Test request without API key."""
    try:
        response = requests.post(
            f"{BASE_URL}/analyze",
            json={"sessionId": "test", "message": {"sender": "test", "text": "test"}},
            timeout=10
        )
        passed = response.status_code == 401
        log_test("Auth: Missing API Key", passed, f"Status: {response.status_code}")
    except Exception as e:
        log_test("Auth: Missing API Key", False, str(e))


def test_authentication_invalid():
    """Test request with invalid API key."""
    try:
        response = requests.post(
            f"{BASE_URL}/analyze",
            headers={"x-api-key": "invalid-key", "Content-Type": "application/json"},
            json={"sessionId": "test", "message": {"sender": "test", "text": "test"}},
            timeout=10
        )
        passed = response.status_code == 403
        log_test("Auth: Invalid API Key", passed, f"Status: {response.status_code}")
    except Exception as e:
        log_test("Auth: Invalid API Key", False, str(e))


def test_bank_fraud_scam():
    """Test detection of bank fraud scam."""
    session_id = f"test-bank-{uuid.uuid4().hex[:8]}"

    try:
        payload = create_message_payload(
            session_id,
            "Your bank account will be blocked today. Verify immediately by sharing your OTP."
        )
        response = make_request("POST", "/analyze", payload)

        passed = (
            response.status_code == 200 and
            response.json().get("status") == "success" and
            response.json().get("reply") is not None
        )

        log_test(
            "Scam Detection: Bank Fraud",
            passed,
            f"Reply: {response.json().get('reply', '')[:50]}..."
        )

        return session_id

    except Exception as e:
        log_test("Scam Detection: Bank Fraud", False, str(e))
        return None


def test_upi_fraud_scam():
    """Test detection of UPI fraud scam."""
    session_id = f"test-upi-{uuid.uuid4().hex[:8]}"

    try:
        payload = create_message_payload(
            session_id,
            "Send Rs 1 to 9876543210@paytm to verify your account and avoid suspension."
        )
        response = make_request("POST", "/analyze", payload)

        passed = (
            response.status_code == 200 and
            response.json().get("status") == "success"
        )

        log_test(
            "Scam Detection: UPI Fraud",
            passed,
            f"Reply: {response.json().get('reply', '')[:50]}..."
        )

        return session_id

    except Exception as e:
        log_test("Scam Detection: UPI Fraud", False, str(e))
        return None


def test_phishing_link_scam():
    """Test detection of phishing link scam."""
    session_id = f"test-phishing-{uuid.uuid4().hex[:8]}"

    try:
        payload = create_message_payload(
            session_id,
            "Click here to verify: https://fake-bank.com/verify?user=victim. Urgent action required!"
        )
        response = make_request("POST", "/analyze", payload)

        passed = (
            response.status_code == 200 and
            response.json().get("status") == "success"
        )

        log_test(
            "Scam Detection: Phishing Link",
            passed,
            f"Reply: {response.json().get('reply', '')[:50]}..."
        )

        return session_id

    except Exception as e:
        log_test("Scam Detection: Phishing Link", False, str(e))
        return None


def test_otp_scam():
    """Test detection of OTP theft scam."""
    session_id = f"test-otp-{uuid.uuid4().hex[:8]}"

    try:
        payload = create_message_payload(
            session_id,
            "Please share the OTP sent to your mobile number to complete verification."
        )
        response = make_request("POST", "/analyze", payload)

        passed = (
            response.status_code == 200 and
            response.json().get("status") == "success"
        )

        log_test(
            "Scam Detection: OTP Theft",
            passed,
            f"Reply: {response.json().get('reply', '')[:50]}..."
        )

        return session_id

    except Exception as e:
        log_test("Scam Detection: OTP Theft", False, str(e))
        return None


def test_non_scam_message():
    """Test handling of non-scam message."""
    session_id = f"test-normal-{uuid.uuid4().hex[:8]}"

    try:
        payload = create_message_payload(
            session_id,
            "Hello, how are you today?",
            sender="user"
        )
        response = make_request("POST", "/analyze", payload)

        passed = (
            response.status_code == 200 and
            response.json().get("status") == "success"
        )

        log_test(
            "Non-Scam Message Handling",
            passed,
            f"Reply: {response.json().get('reply', '')[:50]}..."
        )

        return session_id

    except Exception as e:
        log_test("Non-Scam Message Handling", False, str(e))
        return None


def test_multi_turn_conversation():
    """Test multi-turn conversation tracking."""
    session_id = f"test-multi-{uuid.uuid4().hex[:8]}"

    messages = [
        "Your account has been compromised. We need to verify your identity.",
        "Please share your registered phone number for verification.",
        "Send Rs 1 to 9876543210@paytm to confirm you are the real owner."
    ]

    try:
        history = []
        all_passed = True

        for i, msg in enumerate(messages):
            payload = create_message_payload(session_id, msg, history=history)
            response = make_request("POST", "/analyze", payload)

            if response.status_code != 200:
                all_passed = False
                break

            reply = response.json().get("reply", "")

            # Add to history
            history.append({
                "sender": "scammer",
                "text": msg,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
            history.append({
                "sender": "user",
                "text": reply,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })

            print(f"  Turn {i+1}: Scammer: {msg[:40]}...")
            print(f"           Victim: {reply[:40]}...")

            time.sleep(0.5)  # Small delay between messages

        log_test(
            "Multi-Turn Conversation",
            all_passed,
            f"Completed {len(messages)} turns"
        )

        return session_id

    except Exception as e:
        log_test("Multi-Turn Conversation", False, str(e))
        return None


def test_intelligence_extraction():
    """Test intelligence extraction from messages."""
    session_id = f"test-intel-{uuid.uuid4().hex[:8]}"

    try:
        # Send message with extractable intelligence
        payload = create_message_payload(
            session_id,
            "Call me at +919876543210 or send money to fraudster@paytm. "
            "Account number: 12345678901234. Visit http://scam-site.com/login"
        )
        make_request("POST", "/analyze", payload)

        # Check session for extracted intelligence
        response = make_request("GET", f"/sessions/{session_id}")

        if response.status_code == 200:
            data = response.json()
            intel = data.get("extractedIntelligence", {})

            has_phone = len(intel.get("phoneNumbers", [])) > 0
            has_upi = len(intel.get("upiIds", [])) > 0
            has_link = len(intel.get("phishingLinks", [])) > 0

            passed = has_phone or has_upi or has_link

            log_test(
                "Intelligence Extraction",
                passed,
                f"Phones: {intel.get('phoneNumbers', [])}, "
                f"UPIs: {intel.get('upiIds', [])}, "
                f"Links: {intel.get('phishingLinks', [])}"
            )
        else:
            log_test("Intelligence Extraction", False, f"Status: {response.status_code}")

        return session_id

    except Exception as e:
        log_test("Intelligence Extraction", False, str(e))
        return None


def test_session_management():
    """Test session management endpoints."""
    try:
        # List all sessions
        response = make_request("GET", "/sessions")
        list_passed = response.status_code == 200

        log_test(
            "Session Management: List Sessions",
            list_passed,
            f"Found {len(response.json())} sessions"
        )

    except Exception as e:
        log_test("Session Management: List Sessions", False, str(e))


def test_scam_detection_endpoint():
    """Test the direct scam detection test endpoint."""
    try:
        response = make_request(
            "POST",
            "/test/detect",
            params={"message": "Your account will be blocked. Share OTP now!"}
        )

        if response.status_code == 200:
            data = response.json()
            passed = data.get("is_scam") is True
            log_test(
                "Test Endpoint: Scam Detection",
                passed,
                f"is_scam: {data.get('is_scam')}, confidence: {data.get('confidence')}"
            )
        else:
            log_test("Test Endpoint: Scam Detection", False, f"Status: {response.status_code}")

    except Exception as e:
        log_test("Test Endpoint: Scam Detection", False, str(e))


def test_stats_endpoint():
    """Test the stats endpoint."""
    try:
        response = make_request("GET", "/stats")

        passed = response.status_code == 200 and "total_sessions" in response.json()

        log_test(
            "Stats Endpoint",
            passed,
            f"Stats: {json.dumps(response.json(), indent=2)[:100]}..."
        )

    except Exception as e:
        log_test("Stats Endpoint", False, str(e))


def test_session_end():
    """Test manual session ending."""
    session_id = f"test-end-{uuid.uuid4().hex[:8]}"

    try:
        # Create session with a message
        payload = create_message_payload(
            session_id,
            "Urgent: Verify your bank account now to avoid blocking!"
        )
        make_request("POST", "/analyze", payload)

        # End the session
        response = make_request("POST", f"/sessions/{session_id}/end")

        passed = response.status_code == 200
        log_test(
            "Manual Session End",
            passed,
            f"Response: {response.json()}"
        )

    except Exception as e:
        log_test("Manual Session End", False, str(e))


def cleanup_test_sessions():
    """Clean up test sessions."""
    try:
        response = make_request("GET", "/sessions")
        if response.status_code == 200:
            sessions = response.json()
            for session in sessions:
                if session["sessionId"].startswith("test-"):
                    make_request("DELETE", f"/sessions/{session['sessionId']}")
            print(f"\nCleaned up {len([s for s in sessions if s['sessionId'].startswith('test-')])} test sessions")
    except Exception as e:
        print(f"Cleanup failed: {e}")


# ============================================================================
# Main Test Runner
# ============================================================================

def run_all_tests():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("HONEYPOT SCAM DETECTION API - TEST SUITE")
    print("=" * 70)
    print(f"Target: {BASE_URL}")
    print(f"API Key: {API_KEY[:10]}...")
    print("=" * 70 + "\n")

    # Health & Auth Tests
    print("\n--- Health & Authentication Tests ---\n")
    test_health_check()
    test_authentication_missing()
    test_authentication_invalid()

    # Scam Detection Tests
    print("\n--- Scam Detection Tests ---\n")
    test_bank_fraud_scam()
    test_upi_fraud_scam()
    test_phishing_link_scam()
    test_otp_scam()
    test_non_scam_message()

    # Advanced Tests
    print("\n--- Advanced Tests ---\n")
    test_multi_turn_conversation()
    test_intelligence_extraction()
    test_session_management()

    # Test Endpoints
    print("\n--- Test Endpoints ---\n")
    test_scam_detection_endpoint()
    test_stats_endpoint()
    test_session_end()

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Passed: {test_results['passed']}")
    print(f"Failed: {test_results['failed']}")
    print(f"Total:  {test_results['passed'] + test_results['failed']}")
    print("=" * 70)

    if test_results['failed'] > 0:
        print("\nFailed Tests:")
        for test in test_results['tests']:
            if not test['passed']:
                print(f"  - {test['name']}: {test['details']}")

    # Cleanup
    print("\n--- Cleanup ---")
    cleanup_test_sessions()

    return test_results['failed'] == 0


def run_quick_test():
    """Run a quick test with just a few critical tests."""
    print("\n" + "=" * 70)
    print("HONEYPOT API - QUICK TEST")
    print("=" * 70 + "\n")

    test_health_check()
    test_bank_fraud_scam()
    test_intelligence_extraction()

    print("\n" + "=" * 70)
    print(f"Quick Test: {test_results['passed']} passed, {test_results['failed']} failed")
    print("=" * 70)

    return test_results['failed'] == 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--quick":
        success = run_quick_test()
    else:
        success = run_all_tests()

    sys.exit(0 if success else 1)
