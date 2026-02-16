# IndiaAISummit 
The main root dir is honeypot-agent
# Agentic Honeypot Scam Detection System

An AI-powered honeypot system designed to detect and engage scammers, extracting actionable intelligence while protecting potential victims. Built for the GUVI India Hackathon.

## Overview

This system acts as a "honeypot" that:
1. **Detects** scam messages using keyword analysis and pattern matching
2. **Engages** scammers with realistic AI-generated victim responses
3. **Extracts** intelligence (phone numbers, UPI IDs, bank accounts, phishing links)
4. **Reports** findings to the GUVI platform for further action

## Architecture

```
                                  ┌─────────────────────────────────────┐
                                  │        GUVI Hackathon Platform      │
                                  └──────────────┬──────────────────────┘
                                                 │
                                    POST /analyze │ POST callback
                                                 ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                         HONEYPOT API SERVER                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │   FastAPI    │  │    Scam      │  │     AI       │  │  Intelligence │  │
│  │   Endpoint   │──│  Detector    │──│    Agent     │──│   Extractor   │  │
│  │   /analyze   │  │              │  │   (Gemini)   │  │               │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └───────────────┘  │
│         │                                                      │          │
│         ▼                                                      ▼          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │                      Session Manager                              │    │
│  │   • Conversation History    • Extracted Intelligence              │    │
│  │   • Scam Detection Results  • Session State (active/completed)    │    │
│  └──────────────────────────────────────────────────────────────────┘    │
│                                    │                                      │
│                                    ▼                                      │
│                          ┌──────────────────┐                            │
│                          │  GUVI Callback   │                            │
│                          │  (when complete) │                            │
│                          └──────────────────┘                            │
└────────────────────────────────────────────────────────────────────────────┘
```

## Features

### Scam Detection
- Multi-factor analysis using keywords and patterns
- Detects: Bank fraud, UPI fraud, OTP theft, Phishing, Impersonation
- Confidence scoring (0-100%)
- Real-time pattern matching

### AI Agent (Google Gemini)
- Generates natural, human-like victim responses
- Maintains conversation context
- Adapts to scammer tactics
- Never reveals its true nature

### Intelligence Extraction
- Phone numbers (Indian & International)
- UPI IDs (Paytm, PhonePe, GPay, etc.)
- Bank account numbers
- Phishing URLs/Links
- Suspicious keywords

### Session Management
- Per-session tracking
- Conversation history
- Automatic session termination
- Concurrent session support

## Quick Start

### Prerequisites
- Python 3.9+
- Google Gemini API key ([Get one here](https://ai.google.dev/))

### Installation

```bash
# Clone the repository
cd honeypot-agent

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API keys
```

### Configuration

Edit `.env` file:

```env
# Required
GEMINI_API_KEY=your_gemini_api_key_here
API_SECRET_KEY=your_secret_api_key_here

# Optional
PORT=8000
MAX_MESSAGES_PER_SESSION=20
```

### Running the Server

```bash
# Development mode with auto-reload
uvicorn app.main:app --reload --port 8000

# Production mode
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Running Tests

```bash
# Full test suite
python test_api.py

# Quick test
python test_api.py --quick
```

## API Documentation

### Main Endpoint: POST /analyze

Analyzes a scammer message and returns an AI-generated response.

**Request:**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today.",
    "timestamp": "2026-01-21T10:15:30Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Headers:**
```
Content-Type: application/json
x-api-key: your_secret_api_key
```

**Response:**
```json
{
  "status": "success",
  "reply": "Oh no! Why is my account being blocked? What should I do?"
}
```

### Health Check: GET /

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-01-21T10:00:00Z",
  "active_sessions": 5
}
```

### Debug Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sessions` | GET | List all active sessions |
| `/sessions/{id}` | GET | Get session details |
| `/sessions/{id}` | DELETE | Delete a session |
| `/sessions/{id}/end` | POST | Manually end session |
| `/stats` | GET | System statistics |
| `/test/detect` | POST | Test scam detection |
| `/test/extract` | POST | Test intelligence extraction |
| `/test/response` | POST | Test AI response generation |

## Project Structure

```
honeypot-agent/
├── app/
│   ├── __init__.py             # Package initialization
│   ├── main.py                 # FastAPI application & endpoints
│   ├── config.py               # Configuration & environment variables
│   ├── models.py               # Pydantic models
│   ├── scam_detector.py        # Scam detection logic
│   ├── ai_agent.py             # Gemini AI integration
│   ├── intelligence_extractor.py  # Intelligence extraction
│   ├── session_manager.py      # Session management
│   └── guvi_callback.py        # GUVI callback handler
├── requirements.txt            # Python dependencies
├── .env.example                # Environment template
├── test_api.py                 # Test script
└── README.md                   # This file
```

## Scam Detection Logic

### Keyword Scoring

| Category | Keywords | Score |
|----------|----------|-------|
| High Risk | blocked, suspended, verify, OTP, urgent | 10 pts each |
| Medium Risk | confirm, account, bank, payment, KYC | 5 pts each |

**Threshold:** 15+ points = Scam detected

### Pattern Detection

- **Bank Fraud:** "your account" + "bank" + action word
- **UPI Fraud:** UPI/Paytm/PhonePe + payment request
- **OTP Scam:** Request for OTP/verification code
- **Phishing:** Contains link + urgency
- **Impersonation:** RBI, police, government mentions

## Intelligence Extraction Patterns

### Phone Numbers
- Indian: `+91XXXXXXXXXX` or `9XXXXXXXXX`
- International: `+[country code][number]`

### UPI IDs
- Pattern: `username@bankhandle`
- Validates against known UPI handles

### Bank Accounts
- 9-18 digit numbers with bank context

### URLs
- Full URLs: `https://...`
- Short URLs: `bit.ly/...`, `goo.gl/...`

## Session Lifecycle

```
                    ┌───────────────┐
                    │  New Message  │
                    └───────┬───────┘
                            │
                            ▼
                    ┌───────────────┐
            ┌───────│ Session Exists?│───────┐
            │ No    └───────────────┘  Yes   │
            ▼                                ▼
    ┌───────────────┐               ┌───────────────┐
    │Create Session │               │Update Session │
    └───────┬───────┘               └───────┬───────┘
            │                               │
            └───────────┬───────────────────┘
                        │
                        ▼
                ┌───────────────┐
                │Detect Scam    │
                │Extract Intel  │
                │Generate Reply │
                └───────┬───────┘
                        │
                        ▼
                ┌───────────────┐
            ┌───│ Should End?   │───┐
            │No └───────────────┘Yes│
            │                       │
            ▼                       ▼
    ┌───────────────┐       ┌───────────────┐
    │Return Response│       │End Session    │
    └───────────────┘       │Send Callback  │
                            │Return Response│
                            └───────────────┘
```

### Session End Triggers
- 20+ messages exchanged
- 30 minutes session duration
- 5 minutes inactivity
- Sufficient intelligence extracted

## GUVI Callback Payload

When a session ends, this payload is sent:

```json
{
  "sessionId": "abc123",
  "scamDetected": true,
  "totalMessagesExchanged": 20,
  "extractedIntelligence": {
    "bankAccounts": [],
    "upiIds": ["scammer@paytm"],
    "phishingLinks": ["https://fake-site.com"],
    "phoneNumbers": ["9876543210"],
    "suspiciousKeywords": ["blocked", "verify", "urgent"]
  },
  "agentNotes": "Scammer attempted bank fraud via UPI..."
}
```

## Deployment

### Local Development
```bash
uvicorn app.main:app --reload --port 8000
```

### Production (Gunicorn)
```bash
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
```

### Docker
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Cloud Platforms

**Render:**
- Create new Web Service
- Connect GitHub repo
- Set environment variables
- Deploy

**Railway:**
- `railway init`
- `railway up`

**Google Cloud Run:**
```bash
gcloud run deploy honeypot --source . --region asia-south1
```

## Troubleshooting

### Common Issues

**1. Gemini API Errors**
- Check API key is valid
- Verify quota/billing
- Check safety settings

**2. Authentication Failures**
- Ensure `x-api-key` header is sent
- Verify API_SECRET_KEY matches

**3. No Intelligence Extracted**
- Check message contains extractable data
- Review regex patterns in `intelligence_extractor.py`

### Debug Mode

Set in `.env`:
```env
LOG_LEVEL=DEBUG
```

### API Logs

All requests and responses are logged:
```
2026-01-21 10:15:30 - INFO - Request: POST /analyze
2026-01-21 10:15:31 - INFO - Scam detection: is_scam=True, confidence=0.95
2026-01-21 10:15:32 - INFO - Generated AI response: "Oh no!..."
```

## Performance

- Response time: < 2 seconds
- Concurrent sessions: 100+
- Memory: ~100MB base + ~1KB per session

## Security Considerations

- API key authentication required
- No real personal data stored
- Input sanitization
- Rate limiting (recommended in production)
- HTTPS recommended

## License

MIT License - See LICENSE file

## Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## Support

For issues and feature requests, please create an issue on GitHub.

---

Built with FastAPI, Google Gemini AI, and Pydantic for GUVI India Hackathon 2026.
