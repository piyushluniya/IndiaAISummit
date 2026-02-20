# IntelliBait - Agentic Honeypot for Scam Detection & Intelligence Extraction

An AI-powered honeypot system that detects scams, engages scammers with realistic victim personas, and extracts actionable intelligence. Built for the India AI Summit Hackathon.

## Description

IntelliBait simulates a convincing scam victim to waste scammers' time and extract their operational details (phone numbers, UPI IDs, bank accounts, phishing links, email addresses). The system uses a multi-layer detection engine, adaptive conversation strategies, and Google Gemini AI to maintain natural conversations while systematically eliciting intelligence.

## Tech Stack

- **Language/Framework**: Python 3.9+ / FastAPI
- **AI/LLM**: Google Gemini (gemini-2.5-flash-lite)
- **Key Libraries**: Pydantic (validation), google-generativeai (AI), uvicorn (ASGI server)
- **Detection**: Multi-layer rule engine + ML classifier + NLP pattern matching
- **Deployment**: Render (production), Docker-ready

## Setup Instructions

```bash
# 1. Clone the repository
git clone https://github.com/piyushluniya/IndiaAISummit.git
cd IndiaAISummit/honeypot-agent

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate    # Linux/Mac
# .\venv\Scripts\activate   # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set environment variables
cp .env.example .env
# Edit .env with your API keys:
#   GEMINI_API_KEY=your_gemini_key
#   API_SECRET_KEY=your_api_secret

# 5. Run the application
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## API Endpoint

- **URL**: `https://your-deployed-url.com/analyze` (also accepts `POST /`)
- **Method**: POST
- **Authentication**: `x-api-key` header (required)
- **Content-Type**: `application/json`

### Request Format

```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your account has been compromised...",
    "timestamp": "2026-02-11T10:30:00Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

### Response Format

```json
{
  "status": "success",
  "reply": "Oh no! What happened to my account? What is your name and which branch?"
}
```

### Final Output (Callback)

When a session completes, the system submits:

```json
{
  "sessionId": "abc123",
  "status": "success",
  "scamDetected": true,
  "scamType": "bank_impersonation",
  "confidenceLevel": 0.92,
  "totalMessagesExchanged": 20,
  "engagementDurationSeconds": 120.5,
  "extractedIntelligence": {
    "phoneNumbers": ["+91-9876543210"],
    "bankAccounts": ["1234567890123456"],
    "upiIds": ["scammer.fraud@fakebank"],
    "phishingLinks": ["http://malicious-site.com"],
    "emailAddresses": ["scammer@fake.com"],
    "caseIds": ["REF-12345"],
    "policyNumbers": [],
    "orderNumbers": []
  },
  "engagementMetrics": {
    "engagementDurationSeconds": 120.5,
    "totalMessagesExchanged": 20
  },
  "agentNotes": "Scam types detected: bank_impersonation. Red flags identified: Artificial time pressure and urgency tactics; Impersonation of bank or company official; Request for sensitive credentials (OTP/PIN/CVV/password); Threatening with account suspension or legal consequences; Unsolicited contact from unknown caller claiming authority. Phone numbers extracted: 9876543210. Scammer tactics observed: authority_impersonation, credential_harvesting, threat_intimidation, urgency_pressure."
}
```

## Approach

### How We Detect Scams

The system uses a **4-layer hybrid detection engine**:

1. **Layer 1 - Keyword Scoring** (100+ weighted terms): High-risk terms like "blocked", "OTP", "suspended" score 8-10 pts; medium-risk terms like "account", "verify" score 3-5 pts. Normalized to 0-1.0 confidence.

2. **Layer 2 - Pattern Matching** (18+ regex patterns): Multi-word scam patterns like `"your.*account.*(blocked|suspended)"` for bank impersonation (0.9 weight), `"send.*money.*upi"` for UPI fraud (0.9), `"share.*otp"` for OTP theft (0.95).

3. **Layer 3 - Contextual Analysis**: Analyzes conversation history for escalating threats (+0.3), repeated info requests (+0.25), trust+money combinations (+0.3), and multi-org contradictions (+0.2).

4. **Layer 4 - Feature Scoring**: Structural indicators — urgency words (+0.3), contact info presence (+0.2), links (+0.25), authority impersonation (+0.3), sensitive info requests (+0.4).

**Final confidence** = weighted combination of all layers. Scam threshold: 0.35 (optimized for honeypot — minimizes false negatives).

**Supported Scam Types** (15+ categories): bank_impersonation, upi_fraud, otp_theft, phishing_link, investment_scam, job_scam, prize_lottery, tax_legal, kyc_update, refund_scam, electricity_bill, customs_parcel, crypto_investment, insurance, loan_approval, tech_support, govt_scheme.

### Red Flag Identification

The system identifies and reports 10+ specific red flags in agent notes (aim for 5+ per session):
- **Artificial time pressure**: "urgent", "expire", "last chance", "hurry", "deadline"
- **Government authority impersonation**: Claiming to be from RBI, police, customs, income tax
- **Bank/company official impersonation**: Fake bank officers, fraud departments, customer care
- **Credential harvesting**: Requesting OTP, PIN, CVV, passwords, Aadhaar, PAN
- **Financial extraction**: Requesting money transfers, processing fees, advance payments
- **Threatening language**: Account blocking, legal action, arrest warrants, FIR
- **Suspicious link sharing**: Phishing URLs, shortened links, download requests
- **Social engineering bait**: Fake prizes, cashback, lottery, discounts, offers
- **Fake KYC/verification**: Mandatory KYC updates, identity verification scams
- **Progressive escalation**: Increasingly aggressive information requests
- **Unsolicited contact**: Unknown caller claiming authority

### How We Extract Intelligence

Generic extraction using compiled regex patterns (not hardcoded to test data):

| Data Type | Method | Example |
|-----------|--------|---------|
| Phone Numbers | Indian format regex with prefix handling (+91, 91, 0) | `+91-9876543210`, `98765 43210` |
| UPI IDs | Standard + obfuscated patterns, validated against known handles | `user@paytm`, `user AT gpay` |
| Bank Accounts | 9-18 digit numbers with context-aware validation | `1234567890123456` near "account" |
| Phishing Links | HTTP/HTTPS URLs, short URLs, obfuscated domains | `bit.ly/xxx`, `example[dot]com` |
| Email Addresses | Standard + obfuscated email patterns | `user@domain.com`, `user (at) domain` |
| IFSC Codes | 4-letter + 0 + 6-alphanumeric pattern | `SBIN0001234` |
| Case/Reference IDs | Case no., REF-, CASE-, FIR-, complaint ID patterns | `REF-12345`, `CASE-2026-789` |
| Policy Numbers | Policy no., POL-, LIC-, insurance ID patterns | `POL-987654`, `LIC-2026-123` |
| Order Numbers | Order ID, ORD-, TXN-, invoice patterns | `ORD-2026-789`, `INV-456789` |

### How We Maintain Engagement

The AI agent uses **5 distinct victim personas** (selected per session via hash for consistency):
- **Kamla Devi** (elderly, low tech) — confused, polite, trusting
- **Rahul Sharma** (professional, moderate tech) — busy, asks for verification
- **Priya Patel** (student, high tech) — curious but inexperienced
- **Sunita Verma** (homemaker, low tech) — worried, family-focused
- **Ajay Gupta** (business owner, moderate tech) — direct, demands specifics

**3-stage conversation strategy**:
1. **Early** (turns 1-5): Appear vulnerable, ask who they are, get their phone number
2. **Middle** (turns 6-12): Ask for UPI ID, email, official link, employee ID
3. **Late** (turns 13+): Demand proof, point out inconsistencies, collect remaining intel

**Every response ends with a question** asking for the scammer's details — this is the core information elicitation mechanism.

### Auto-Finalization

A 5-second inactivity timer ensures the final output is submitted even if the conversation ends abruptly. This guarantees the callback reaches the evaluation platform within its 10-second window.

## Project Structure

```
honeypot-agent/
├── app/
│   ├── __init__.py                  # Package init, version
│   ├── main.py                      # FastAPI app, endpoints, auto-finalization timer
│   ├── config.py                    # Environment config, keywords, patterns
│   ├── models.py                    # Pydantic schemas with validation
│   ├── scam_detector.py             # 4-layer hybrid scam detection engine
│   ├── ai_agent.py                  # Gemini AI victim persona + elicitation
│   ├── intelligence_extractor.py    # Regex-based intel extraction (phone, UPI, etc.)
│   ├── conversation_strategy.py     # Persona selection, stage management
│   ├── session_manager.py           # Thread-safe session lifecycle
│   ├── urgency_detector.py          # Pressure tactics analysis
│   ├── translator.py                # Hindi/English translation
│   ├── ml_classifier.py             # Optional ML scam classifier
│   ├── guvi_callback.py             # Final output submission with retry
│   └── static/                      # Static assets (favicon, UI)
├── requirements.txt                 # Python dependencies
├── .env.example                     # Environment variables template
├── .gitignore                       # Git ignore rules
├── render.yaml                      # Render deployment config
├── eval_scenarios.py                # Self-evaluation test script
├── test_api.py                      # API test suite
└── README.md                        # This file
```

## Error Handling

The system implements a **never-crash guarantee**:

- **Input validation**: Pydantic field validators on `sessionId`, `sender`, `text` with automatic sanitization and truncation (5000 char limit)
- **Layer-by-layer try/except**: Each processing step (detection, extraction, AI generation) has independent error handling with safe fallbacks
- **AI fallback chain**: If Gemini fails → smart context-aware fallback responses → generic safe responses
- **Retry with backoff**: Gemini API calls retry up to 3 times with exponential backoff
- **Session resilience**: Thread-safe session management with RLock, automatic cleanup of stale sessions
- **Callback reliability**: Final output submission retries 3 times with exponential backoff
- **Auto-finalization**: Background timer ensures final output is sent even if the evaluator stops sending messages

The API always returns `200 OK` with a valid `{"status": "success", "reply": "..."}` response — it never crashes or returns error codes for valid requests.

## Testing

```bash
# Run self-evaluation against all 3 sample scenarios
python eval_scenarios.py

# Quick endpoint test
python test_api.py

# Manual cURL test
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -H "x-api-key: your-api-key" \
  -d '{"sessionId":"test-1","message":{"sender":"scammer","text":"Your account is blocked!"},"conversationHistory":[],"metadata":{"channel":"SMS","language":"English","locale":"IN"}}'
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GEMINI_API_KEY` | Yes | — | Google Gemini API key |
| `API_SECRET_KEY` | Yes | `default-secret-key` | API authentication key |
| `PORT` | No | `8000` | Server port |
| `GEMINI_MODEL` | No | `gemini-2.5-flash-lite` | Gemini model name |
| `MAX_MESSAGES_PER_SESSION` | No | `20` | Max messages before session ends |
| `SESSION_TIMEOUT_MINUTES` | No | `30` | Session duration limit |
| `LOG_LEVEL` | No | `INFO` | Logging level |
| `GUVI_CALLBACK_URL` | No | `https://hackathon.guvi.in/...` | Callback endpoint |

## Deployment

### Render (Production)
The `render.yaml` is pre-configured. Connect the GitHub repo and set environment variables.

### Docker
```bash
docker build -t intellibait .
docker run -p 8000:8000 --env-file .env intellibait
```

### Production
```bash
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
```

---

Built with FastAPI, Google Gemini AI, and Pydantic for India AI Summit Hackathon 2026.
