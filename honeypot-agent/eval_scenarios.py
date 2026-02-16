"""
Self-evaluation script matching the hackathon evaluation system.
Tests all 3 sample scenarios with multi-turn conversation simulation.
"""

import requests
import uuid
import json
import time
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Configuration
BASE_URL = os.getenv("EVAL_BASE_URL", "http://localhost:8000")
API_KEY = os.getenv("API_SECRET_KEY", "default-secret-key")
ENDPOINT = f"{BASE_URL}/analyze"

HEADERS = {
    "Content-Type": "application/json",
    "x-api-key": API_KEY
}

# All 3 sample scenarios
SCENARIOS = [
    {
        "scenarioId": "bank_fraud",
        "name": "Bank Fraud Detection",
        "scamType": "bank_fraud",
        "initialMessage": "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
        "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "bankAccount": "1234567890123456",
            "upiId": "scammer.fraud@fakebank",
            "phoneNumber": "+91-9876543210"
        },
        "followUps": [
            "I am calling from SBI Fraud Department. My employee ID is SBI-FRD-4521. Your account {bankAccount} has suspicious transactions. Please verify your identity immediately.",
            "Sir/Madam, this is very urgent. I can see unauthorized transactions of Rs. 50,000 on your account. You can reach me at {phoneNumber} for verification. Please share your OTP now.",
            "I understand your concern. Let me verify - your account ending with 3456 has been flagged. You can also make a small verification payment to our secure UPI: {upiId}",
            "Time is running out! Your account will be permanently blocked. This is your last chance. I am Senior Manager Sharma from SBI Main Branch. Share OTP or visit nearest branch NOW.",
            "Ma'am/Sir, I am trying to help you. If you don't verify in next 30 minutes, you will lose all your money. Please cooperate with us. What is the OTP you received?",
            "Look, I can see your account details here. Account number {bankAccount}, IFSC SBIN0001234. Just confirm the OTP and your account will be safe. We are recording this call.",
            "This is my direct number {phoneNumber}. You can call me back anytime. But first, let me secure your account. The OTP is just for verification, your money is safe with SBI.",
            "Final warning - RBI guidelines require immediate verification for flagged accounts. Failure to comply will result in account seizure. Please share OTP immediately.",
            "I have escalated this to our cyber cell. They will contact you shortly. Meanwhile, transfer Rs. 1 to {upiId} to verify your account ownership. This is standard SBI procedure."
        ]
    },
    {
        "scenarioId": "upi_fraud",
        "name": "UPI Fraud Multi-turn",
        "scamType": "upi_fraud",
        "initialMessage": "Congratulations! You have won a cashback of Rs. 5000 from Paytm. To claim your reward, please verify your UPI details. This is from official customer support.",
        "metadata": {"channel": "WhatsApp", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "upiId": "cashback.scam@fakeupi",
            "phoneNumber": "+91-8765432109"
        },
        "followUps": [
            "Thank you for responding! To process your Rs. 5000 cashback, we need to verify your Paytm account. Please share your registered mobile number.",
            "Great! Your cashback is being processed. For security purposes, please send Rs. 1 to our verification UPI ID: {upiId}. This confirms your identity.",
            "The Rs. 1 is just for verification and will be refunded along with your Rs. 5000 cashback within 24 hours. This is standard Paytm procedure. Our support number is {phoneNumber}.",
            "I see you haven't completed the verification yet. Your cashback of Rs. 5000 will expire in 15 minutes. Please hurry! Send Rs. 1 to {upiId} now.",
            "If you're having trouble, you can call our customer support at {phoneNumber}. We can guide you through the process step by step.",
            "As a special offer, if you verify now, we'll double your cashback to Rs. 10,000! Just send Rs. 1 to {upiId} and the amount will be credited immediately.",
            "This is an automated reminder. Your Paytm cashback reward #PTM-CB-78945 is about to expire. Last chance to claim Rs. 5000. Verify via {upiId}.",
            "Sir/Madam, I am supervisor Rajesh from Paytm rewards team. Your cashback has been approved. Just complete the small verification and enjoy your reward!",
            "We are closing unclaimed rewards today. After this, you won't be able to claim your Rs. 5000. Don't miss out! UPI: {upiId}, Support: {phoneNumber}"
        ]
    },
    {
        "scenarioId": "phishing_link",
        "name": "Phishing Link Detection",
        "scamType": "phishing",
        "initialMessage": "You have been selected for iPhone 15 Pro at just Rs. 999! Click here to claim: http://amaz0n-deals.fake-site.com/claim?id=12345. Offer expires in 10 minutes!",
        "metadata": {"channel": "Email", "language": "English", "locale": "IN"},
        "weight": 10,
        "maxTurns": 10,
        "fakeData": {
            "phishingLink": "http://amaz0n-deals.fake-site.com/claim?id=12345",
            "emailAddress": "offers@fake-amazon-deals.com"
        },
        "followUps": [
            "This is a verified Amazon partner offer! The iPhone 15 Pro is available at 95% discount for selected customers. Visit http://amaz0n-deals.fake-site.com/claim?id=12345 to claim now.",
            "For any queries, email us at {emailAddress}. This offer is legitimate and backed by Amazon's satisfaction guarantee. Limited stock remaining!",
            "We noticed you haven't claimed your iPhone yet. Only 3 units left! Click http://amaz0n-deals.fake-site.com/claim?id=12345 and enter your shipping details.",
            "To complete your purchase, you need to pay just Rs. 999 processing fee. Visit the link or reply to {emailAddress} with your details.",
            "This is your final reminder! The iPhone 15 Pro offer expires TODAY. Don't miss this incredible deal. http://amaz0n-deals.fake-site.com/claim?id=12345",
            "Many customers have already claimed their iPhones. Check reviews at http://amaz0n-deals.fake-site.com/reviews. Contact {emailAddress} for support.",
            "Special bonus: Claim now and get free AirPods Pro! Total value Rs. 1,50,000 for just Rs. 999. Click http://amaz0n-deals.fake-site.com/claim?id=12345",
            "Dear valued customer, we are extending the offer by 1 hour just for you. This is a one-time exception. Please visit the link to claim your iPhone 15 Pro.",
            "Last message: Your reservation #AMZ-99812 for iPhone 15 Pro will be cancelled in 30 minutes. Claim at http://amaz0n-deals.fake-site.com/claim?id=12345 or email {emailAddress}"
        ]
    }
]


def run_scenario(scenario):
    """Run a single scenario evaluation."""
    session_id = str(uuid.uuid4())
    conversation_history = []
    start_time = time.time()

    print(f"\n{'='*70}")
    print(f"SCENARIO: {scenario['name']} ({scenario['scenarioId']})")
    print(f"Session: {session_id}")
    print(f"{'='*70}")

    responses = []

    for turn in range(scenario["maxTurns"]):
        # Determine scammer message
        if turn == 0:
            scammer_msg = scenario["initialMessage"]
        else:
            if turn - 1 < len(scenario["followUps"]):
                template = scenario["followUps"][turn - 1]
                # Replace fake data placeholders
                for key, val in scenario["fakeData"].items():
                    template = template.replace(f"{{{key}}}", val)
                scammer_msg = template
            else:
                break

        timestamp = datetime.utcnow().isoformat() + "Z"
        message = {
            "sender": "scammer",
            "text": scammer_msg,
            "timestamp": timestamp
        }

        request_body = {
            "sessionId": session_id,
            "message": message,
            "conversationHistory": conversation_history,
            "metadata": scenario["metadata"]
        }

        print(f"\n--- Turn {turn + 1} ---")
        print(f"  Scammer: {scammer_msg[:100]}{'...' if len(scammer_msg) > 100 else ''}")

        try:
            resp = requests.post(ENDPOINT, headers=HEADERS, json=request_body, timeout=30)

            if resp.status_code != 200:
                print(f"  ERROR: Status {resp.status_code}: {resp.text[:200]}")
                break

            data = resp.json()
            reply = data.get("reply") or data.get("message") or data.get("text")

            if not reply:
                print(f"  ERROR: No reply field. Response: {data}")
                break

            print(f"  Honeypot: {reply[:100]}{'...' if len(reply) > 100 else ''}")
            responses.append({"turn": turn + 1, "reply": reply, "status": data.get("status")})

            # Update conversation history
            conversation_history.append(message)
            conversation_history.append({
                "sender": "user",
                "text": reply,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })

            time.sleep(0.5)  # Small delay between turns

        except requests.exceptions.Timeout:
            print("  ERROR: Timeout (>30s)")
            break
        except Exception as e:
            print(f"  ERROR: {e}")
            break

    end_time = time.time()
    duration = end_time - start_time
    total_messages = len(conversation_history)

    # Wait for auto-finalize (inactivity timer is 5s)
    print(f"\n  Waiting 8s for auto-finalization...")
    time.sleep(8)

    # Fetch session data
    print(f"  Fetching session data...")
    try:
        session_resp = requests.get(
            f"{BASE_URL}/sessions/{session_id}",
            headers=HEADERS,
            timeout=10
        )
        if session_resp.status_code == 200:
            session_data = session_resp.json()
        else:
            print(f"  WARNING: Could not fetch session: {session_resp.status_code}")
            session_data = {}
    except Exception as e:
        print(f"  WARNING: Session fetch error: {e}")
        session_data = {}

    # Build final output (simulating what the callback sends)
    final_output = {
        "sessionId": session_id,
        "status": "success",
        "scamDetected": session_data.get("scamDetected", False),
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": session_data.get("extractedIntelligence", {}),
        "engagementMetrics": {
            "engagementDurationSeconds": duration,
            "totalMessagesExchanged": total_messages
        },
        "agentNotes": session_data.get("agentNotes", "")
    }

    # Score it
    score = evaluate_final_output(final_output, scenario, conversation_history, duration)
    return score, final_output, responses


def evaluate_final_output(final_output, scenario, conversation_history, duration):
    """Evaluate using the same logic as the hackathon evaluator."""
    score = {
        "scamDetection": 0,
        "intelligenceExtraction": 0,
        "engagementQuality": 0,
        "responseStructure": 0,
        "total": 0,
        "details": {}
    }

    # 1. Scam Detection (20 points)
    if final_output.get("scamDetected", False):
        score["scamDetection"] = 20
        score["details"]["scamDetected"] = "YES (20 pts)"
    else:
        score["details"]["scamDetected"] = "NO (0 pts)"

    # 2. Intelligence Extraction (40 points)
    extracted = final_output.get("extractedIntelligence", {})
    fake_data = scenario.get("fakeData", {})

    key_mapping = {
        "bankAccount": "bankAccounts",
        "upiId": "upiIds",
        "phoneNumber": "phoneNumbers",
        "phishingLink": "phishingLinks",
        "emailAddress": "emailAddresses"
    }

    intel_details = {}
    for fake_key, fake_value in fake_data.items():
        output_key = key_mapping.get(fake_key, fake_key)
        extracted_values = extracted.get(output_key, [])

        found = False
        if isinstance(extracted_values, list):
            # Check if fake value is contained in any extracted value
            fake_clean = fake_value.replace("+91-", "").replace("+91", "").replace("-", "").replace(" ", "")
            for v in extracted_values:
                v_clean = str(v).replace("+91-", "").replace("+91", "").replace("-", "").replace(" ", "")
                if fake_clean in v_clean or v_clean in fake_clean:
                    found = True
                    break
                if fake_value in str(v) or str(v) in fake_value:
                    found = True
                    break

        if found:
            score["intelligenceExtraction"] += 10
            intel_details[fake_key] = f"FOUND ({fake_value}) -> +10 pts"
        else:
            intel_details[fake_key] = f"MISSING ({fake_value}) in {extracted_values} -> 0 pts"

    score["intelligenceExtraction"] = min(score["intelligenceExtraction"], 40)
    score["details"]["intelligence"] = intel_details

    # 3. Engagement Quality (20 points)
    metrics = final_output.get("engagementMetrics", {})
    eng_duration = metrics.get("engagementDurationSeconds", 0)
    eng_messages = metrics.get("totalMessagesExchanged", 0)

    eng_details = []
    if eng_duration > 0:
        score["engagementQuality"] += 5
        eng_details.append(f"duration > 0: YES (+5)")
    else:
        eng_details.append(f"duration > 0: NO")

    if eng_duration > 60:
        score["engagementQuality"] += 5
        eng_details.append(f"duration > 60s ({eng_duration:.1f}s): YES (+5)")
    else:
        eng_details.append(f"duration > 60s ({eng_duration:.1f}s): NO")

    if eng_messages > 0:
        score["engagementQuality"] += 5
        eng_details.append(f"messages > 0: YES ({eng_messages}) (+5)")
    else:
        eng_details.append(f"messages > 0: NO")

    if eng_messages >= 5:
        score["engagementQuality"] += 5
        eng_details.append(f"messages >= 5: YES ({eng_messages}) (+5)")
    else:
        eng_details.append(f"messages >= 5: NO ({eng_messages})")

    score["details"]["engagement"] = eng_details

    # 4. Response Structure (20 points)
    required_fields = ["status", "scamDetected", "extractedIntelligence"]
    optional_fields = ["engagementMetrics", "agentNotes"]

    struct_details = []
    for field in required_fields:
        if field in final_output:
            score["responseStructure"] += 5
            struct_details.append(f"{field}: PRESENT (+5)")
        else:
            struct_details.append(f"{field}: MISSING (0)")

    for field in optional_fields:
        if field in final_output and final_output[field]:
            score["responseStructure"] += 2.5
            struct_details.append(f"{field}: PRESENT (+2.5)")
        else:
            struct_details.append(f"{field}: MISSING (0)")

    score["responseStructure"] = min(score["responseStructure"], 20)
    score["details"]["structure"] = struct_details

    # Total
    score["total"] = (
        score["scamDetection"] +
        score["intelligenceExtraction"] +
        score["engagementQuality"] +
        score["responseStructure"]
    )

    return score


def print_score(scenario_name, score):
    """Print formatted score breakdown."""
    print(f"\n{'-'*50}")
    print(f"SCORE: {scenario_name}")
    print(f"{'-'*50}")

    print(f"\n  1. Scam Detection:          {score['scamDetection']:5.1f} / 20")
    print(f"     {score['details']['scamDetected']}")

    print(f"\n  2. Intelligence Extraction: {score['intelligenceExtraction']:5.1f} / 40")
    for key, val in score["details"]["intelligence"].items():
        print(f"     {key}: {val}")

    print(f"\n  3. Engagement Quality:      {score['engagementQuality']:5.1f} / 20")
    for detail in score["details"]["engagement"]:
        print(f"     {detail}")

    print(f"\n  4. Response Structure:       {score['responseStructure']:5.1f} / 20")
    for detail in score["details"]["structure"]:
        print(f"     {detail}")

    print(f"\n  {'='*40}")
    print(f"  TOTAL SCORE:                {score['total']:5.1f} / 100")
    print(f"  {'='*40}")


def main():
    print("=" * 70)
    print("HONEYPOT API EVALUATION - 3 Sample Scenarios")
    print(f"Endpoint: {ENDPOINT}")
    print("=" * 70)

    # Quick health check
    try:
        health = requests.get(f"{BASE_URL}/health", timeout=5)
        if health.status_code == 200:
            print(f"API Health: OK ({health.json().get('version', '?')})")
        else:
            print(f"API Health: WARNING (status {health.status_code})")
    except Exception as e:
        print(f"API Health: FAILED ({e})")
        print("Make sure the server is running: uvicorn app.main:app --port 8000")
        return

    all_scores = []

    for scenario in SCENARIOS:
        score, final_output, responses = run_scenario(scenario)
        print_score(scenario["name"], score)

        # Print extracted intelligence
        intel = final_output.get("extractedIntelligence", {})
        print(f"\n  Extracted Intelligence:")
        for key, vals in intel.items():
            if vals and key != "suspiciousKeywords":
                print(f"    {key}: {vals}")

        print(f"\n  Agent Notes: {final_output.get('agentNotes', 'N/A')[:200]}")
        print(f"  Session Status: {final_output.get('status', 'N/A')}")

        all_scores.append({
            "scenario": scenario["name"],
            "scenarioId": scenario["scenarioId"],
            "weight": scenario["weight"],
            "score": score
        })

    # Final weighted score
    print(f"\n\n{'='*70}")
    print("FINAL WEIGHTED SCORE")
    print(f"{'='*70}")

    total_weight = sum(s["weight"] for s in all_scores)
    weighted_sum = 0

    print(f"\n  {'Scenario':<30} {'Score':>8} {'Weight':>8} {'Contribution':>14}")
    print(f"  {'-'*60}")

    for s in all_scores:
        w = s["weight"] / total_weight
        contribution = s["score"]["total"] * w
        weighted_sum += contribution
        print(f"  {s['scenario']:<30} {s['score']['total']:>7.1f} {s['weight']:>7}   {contribution:>12.2f}")

    print(f"  {'-'*60}")
    print(f"  {'FINAL SCORE':<30} {'':>8} {'':>8} {weighted_sum:>12.2f} / 100")
    print(f"  {'='*60}")

    # Category breakdown
    print(f"\n  Category Breakdown (averaged):")
    categories = ["scamDetection", "intelligenceExtraction", "engagementQuality", "responseStructure"]
    cat_names = ["Scam Detection", "Intelligence Extraction", "Engagement Quality", "Response Structure"]
    cat_max = [20, 40, 20, 20]

    for cat, name, mx in zip(categories, cat_names, cat_max):
        avg = sum(s["score"][cat] for s in all_scores) / len(all_scores)
        print(f"    {name:<25} {avg:>5.1f} / {mx}")


if __name__ == "__main__":
    main()
