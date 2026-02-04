#!/usr/bin/env python3
"""
Interactive Chat Test for Honeypot Scam Detection System.
Simulates a scammer conversation with the AI victim.
"""

import os
import uuid
import requests
from datetime import datetime

# Configuration
BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
API_KEY = os.getenv("API_SECRET_KEY", "my-super-secret-honeypot-key-2026")

def send_message(session_id: str, message: str, history: list) -> dict:
    """Send a message to the honeypot API."""
    url = f"{BASE_URL}/analyze"
    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY
    }

    payload = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": message,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        },
        "conversationHistory": history,
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }

    response = requests.post(url, headers=headers, json=payload, timeout=30)
    return response.json()

def get_session_info(session_id: str) -> dict:
    """Get session information."""
    url = f"{BASE_URL}/sessions/{session_id}"
    headers = {"x-api-key": API_KEY}
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code == 200:
        return response.json()
    return {}

def print_banner():
    """Print welcome banner."""
    print("\n" + "=" * 60)
    print("  HONEYPOT SCAM DETECTION - INTERACTIVE TEST")
    print("=" * 60)
    print("You are the SCAMMER. Type messages to try to scam the victim.")
    print("The AI will respond as a confused, worried victim.")
    print("-" * 60)
    print("Commands:")
    print("  /info    - Show session info (extracted intelligence)")
    print("  /new     - Start a new session")
    print("  /quit    - Exit the chat")
    print("=" * 60 + "\n")

def main():
    """Main interactive loop."""
    print_banner()

    session_id = f"interactive-{uuid.uuid4().hex[:8]}"
    history = []
    message_count = 0

    print(f"Session ID: {session_id}\n")
    print("Start typing as a scammer. The victim will respond.\n")

    while True:
        try:
            # Get scammer input
            user_input = input("\n[SCAMMER] You: ").strip()

            if not user_input:
                continue

            # Handle commands
            if user_input.lower() == "/quit":
                print("\nExiting chat. Goodbye!")
                break

            if user_input.lower() == "/new":
                session_id = f"interactive-{uuid.uuid4().hex[:8]}"
                history = []
                message_count = 0
                print(f"\n--- New session started: {session_id} ---\n")
                continue

            if user_input.lower() == "/info":
                info = get_session_info(session_id)
                if info:
                    print("\n--- SESSION INFO ---")
                    print(f"Messages: {info.get('messageCount', 0)}")
                    print(f"Scam Detected: {info.get('scamDetected', False)}")
                    print(f"Scam Types: {info.get('detectedScamTypes', [])}")
                    intel = info.get('extractedIntelligence', {})
                    print(f"Phones: {intel.get('phoneNumbers', [])}")
                    print(f"UPI IDs: {intel.get('upiIds', [])}")
                    print(f"Links: {intel.get('phishingLinks', [])}")
                    print(f"Keywords: {intel.get('suspiciousKeywords', [])}")
                    print("--------------------\n")
                else:
                    print("No session info available yet.")
                continue

            # Send message to API
            message_count += 1
            print(f"\n[Sending message {message_count}...]")

            response = send_message(session_id, user_input, history)

            if response.get("status") == "success":
                victim_reply = response.get("reply", "...")
                print(f"\n[VICTIM] AI: {victim_reply}")

                # Update history
                history.append({
                    "sender": "scammer",
                    "text": user_input,
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                })
                history.append({
                    "sender": "user",
                    "text": victim_reply,
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                })
            else:
                print(f"\nError: {response}")

        except KeyboardInterrupt:
            print("\n\nExiting chat. Goodbye!")
            break
        except Exception as e:
            print(f"\nError: {e}")

if __name__ == "__main__":
    main()
