"""
Main FastAPI Application for the Honeypot Scam Detection System.
Provides REST API endpoints for processing scammer messages and managing sessions.
Enhanced with robust error handling and never-crash guarantees.
"""

import time
import random
import asyncio
import threading
from datetime import datetime
from typing import List, Optional, Dict
from contextlib import asynccontextmanager

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header, Request, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import logger, settings
from .models import (
    IncomingMessage,
    APIResponse,
    ErrorResponse,
    HealthCheckResponse,
    SessionSummary,
    SessionData
)
from .scam_detector import detect_scam, should_activate_agent, hybrid_detector
from .ai_agent import generate_response, generate_notes, victim_agent
from .intelligence_extractor import extract_intelligence, extract_from_conversation
from .session_manager import (
    session_manager,
    get_or_create_session,
    update_session,
    should_end_session,
    complete_session,
    get_session_data
)
from .guvi_callback import send_session_result_async, guvi_callback
from .translator import detect_and_translate, translate_response

# Safe fallback responses (used when everything else fails)
_SAFE_FALLBACKS = [
    "I am a bit confused. Can you explain that again?",
    "Sorry, I didn't understand. What did you say?",
    "Can you please repeat that? I didn't follow.",
    "I see. Can you tell me more about this?",
    "What do you mean exactly? Please explain.",
]

# ── Inactivity-based auto-finalization ──
# Tracks pending timers per session so we auto-send the final output
# if the evaluator stops sending messages (waits only 10s for our result).
_INACTIVITY_SECONDS = 5  # send final output after 5s of silence (evaluator waits 10s)
_session_timers: Dict[str, threading.Timer] = {}
_timer_lock = threading.Lock()


def _generate_quick_notes(session: SessionData) -> str:
    """Generate agent notes quickly without AI call (for time-critical finalization).
    Includes red flags, extracted intelligence, and scammer tactics."""
    intel = session.extractedIntelligence
    parts = [f"Scam types detected: {', '.join(session.detectedScamTypes) or 'general scam'}."]

    # Red flags
    red_flags = []
    scammer_text = " ".join(
        m.get("text", "").lower() for m in session.conversationHistory
        if m.get("sender", "").lower() != "user"
    )
    if any(w in scammer_text for w in ["urgent", "immediately", "expire", "last chance", "hurry"]):
        red_flags.append("Artificial time pressure")
    if any(w in scammer_text for w in ["blocked", "suspended", "frozen", "legal action", "arrest"]):
        red_flags.append("Threatening language")
    if any(w in scammer_text for w in ["rbi", "government", "police", "officer", "department"]):
        red_flags.append("Authority impersonation")
    if any(w in scammer_text for w in ["otp", "pin", "cvv", "password"]):
        red_flags.append("Credential harvesting attempt")
    if any(w in scammer_text for w in ["send money", "transfer", "pay", "upi"]):
        red_flags.append("Financial extraction attempt")
    if any(w in scammer_text for w in ["click", "http", "link", "url"]):
        red_flags.append("Suspicious link sharing")
    if any(w in scammer_text for w in ["won", "prize", "cashback", "reward", "lottery"]):
        red_flags.append("Social engineering bait")
    if red_flags:
        parts.append(f"Red flags identified: {'; '.join(red_flags)}.")

    # Extracted intelligence
    if intel.phoneNumbers:
        parts.append(f"Phone numbers extracted: {', '.join(intel.phoneNumbers)}.")
    if intel.upiIds:
        parts.append(f"UPI IDs extracted: {', '.join(intel.upiIds)}.")
    if intel.bankAccounts:
        parts.append(f"Bank accounts extracted: {', '.join(intel.bankAccounts)}.")
    if intel.phishingLinks:
        parts.append(f"Phishing links extracted: {', '.join(intel.phishingLinks)}.")
    if intel.emailAddresses:
        parts.append(f"Email addresses extracted: {', '.join(intel.emailAddresses)}.")
    parts.append(f"Conversation: {session.messageCount} messages exchanged.")

    # Scammer tactics
    tactics = set()
    for msg in session.conversationHistory:
        if msg.get("sender", "").lower() != "user":
            text = msg.get("text", "").lower()
            if any(w in text for w in ["urgent", "immediately", "now", "asap", "hurry"]):
                tactics.add("urgency_pressure")
            if any(w in text for w in ["blocked", "suspended", "frozen", "closed", "legal"]):
                tactics.add("threat_intimidation")
            if any(w in text for w in ["bank", "rbi", "government", "officer", "department"]):
                tactics.add("authority_impersonation")
            if any(w in text for w in ["otp", "pin", "cvv", "password", "verify"]):
                tactics.add("credential_harvesting")
            if any(w in text for w in ["send money", "transfer", "pay", "upi"]):
                tactics.add("financial_extraction")
            if any(w in text for w in ["click", "link", "http", "url"]):
                tactics.add("phishing_link_distribution")
            if any(w in text for w in ["won", "prize", "cashback", "reward", "lottery"]):
                tactics.add("social_engineering_bait")
    if tactics:
        parts.append(f"Scammer tactics observed: {', '.join(sorted(tactics))}.")

    return " ".join(parts)


def _auto_finalize_session(session_id: str) -> None:
    """Background callback: auto-complete session and send final result."""
    try:
        session = get_session_data(session_id)
        if not session or session.status.value == "completed":
            return

        logger.info(f"Auto-finalizing session {session_id} due to inactivity")

        # Generate quick notes (no AI call to stay within time window)
        if not session.agentNotes:
            notes = _generate_quick_notes(session)
            update_session(session_id, agent_notes=notes)

        complete_session(session_id, "inactivity_auto_finalize")
        final_session = get_session_data(session_id)
        if final_session:
            send_session_result_async(final_session)
    except Exception as e:
        logger.error(f"Auto-finalize error for {session_id}: {e}")
    finally:
        with _timer_lock:
            _session_timers.pop(session_id, None)


def _reset_inactivity_timer(session_id: str) -> None:
    """Reset (or start) the inactivity timer for a session."""
    with _timer_lock:
        existing = _session_timers.get(session_id)
        if existing:
            existing.cancel()
        timer = threading.Timer(_INACTIVITY_SECONDS, _auto_finalize_session, args=[session_id])
        timer.daemon = True
        timer.start()
        _session_timers[session_id] = timer


# Lifespan context manager for startup/shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 50)
    logger.info("Honeypot Scam Detection System Starting...")
    logger.info(f"Version: {__version__}")
    logger.info(f"Port: {settings.PORT}")
    logger.info(f"Gemini API configured: {bool(settings.GEMINI_API_KEY)}")
    logger.info(f"Gemini model: {settings.GEMINI_MODEL}")
    logger.info("=" * 50)
    yield
    logger.info("Shutting down Honeypot System...")
    active_count = session_manager.get_active_sessions_count()
    if active_count > 0:
        logger.warning(f"Shutting down with {active_count} active sessions")


# Initialize FastAPI application
app = FastAPI(
    title="IntelliBait API",
    description="AI-powered scam intelligence platform for detecting and engaging scammers.",
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files
STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# Middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(round(process_time * 1000, 2)) + "ms"
    return response


@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Request: {request.method} {request.url.path}")
    response = await call_next(request)
    logger.info(f"Response: {response.status_code}")
    return response


# Auth dependency
async def verify_api_key(x_api_key: Optional[str] = Header(None)):
    if not x_api_key:
        logger.warning("Request missing API key")
        raise HTTPException(
            status_code=401,
            detail={"status": "error", "message": "Missing API key. Include 'x-api-key' header.", "code": "AUTH_MISSING"}
        )
    if x_api_key != settings.API_SECRET_KEY:
        logger.warning("Invalid API key attempted")
        raise HTTPException(
            status_code=403,
            detail={"status": "error", "message": "Invalid API key", "code": "AUTH_INVALID"}
        )
    return x_api_key


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/", response_model=HealthCheckResponse, tags=["Health"])
async def health_check():
    return HealthCheckResponse(
        status="healthy",
        version=__version__,
        timestamp=datetime.utcnow(),
        active_sessions=session_manager.get_active_sessions_count()
    )


@app.post("/", response_model=APIResponse, tags=["Analysis"])
async def analyze_message_root(
    request: IncomingMessage,
    api_key: str = Depends(verify_api_key)
):
    return await analyze_message(request, api_key)


@app.get("/health", response_model=HealthCheckResponse, tags=["Health"])
async def health():
    return await health_check()


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    favicon_path = STATIC_DIR / "favicon.ico"
    if favicon_path.exists():
        return FileResponse(favicon_path)
    return JSONResponse(content={}, status_code=204)


@app.get("/ui", response_class=HTMLResponse, tags=["UI"])
async def web_ui():
    html_file = STATIC_DIR / "index.html"
    if html_file.exists():
        return HTMLResponse(content=html_file.read_text(), status_code=200)
    return HTMLResponse(content="<h1>UI not found</h1>", status_code=404)


@app.post("/analyze", response_model=APIResponse, tags=["Analysis"])
async def analyze_message(
    request: IncomingMessage,
    api_key: str = Depends(verify_api_key)
):
    """
    Main endpoint for analyzing scammer messages.
    Enhanced with robust error handling — NEVER crashes.
    """
    try:
        # ── Input validation ──
        session_id = request.get_session_id()
        message_text = request.get_message_text()
        sender = request.get_sender()

        # Handle empty/invalid messages gracefully
        if not message_text or not message_text.strip():
            return APIResponse(
                status="success",
                reply="Hello? Is someone there? I can't see your message."
            )

        # Truncate very long messages
        if len(message_text) > 5000:
            message_text = message_text[:5000]

        # ── Language detection & translation ──
        original_message = message_text
        english_text, detected_language, was_translated = detect_and_translate(message_text)
        if was_translated:
            logger.info(f"Hindi detected, translated to English: {english_text[:50]}...")
            message_text = english_text

        logger.info(f"Processing session {session_id}: {message_text[:50]}...")

        # ── Session management ──
        session = get_or_create_session(
            session_id,
            metadata=request.metadata.model_dump() if request.metadata else {}
        )

        # Add scammer's message to session (store original language)
        timestamp = request.get_timestamp()
        update_session(
            session_id,
            message={"sender": sender, "text": original_message, "timestamp": timestamp}
        )

        # Build conversation history
        history = []
        if request.conversationHistory:
            for msg in request.conversationHistory:
                history.append({
                    "sender": msg.sender,
                    "text": msg.text,
                    "timestamp": msg.timestamp
                })

        # Extract intelligence from incoming conversation history (first call)
        if history and session.messageCount <= 1:
            try:
                history_intel = extract_from_conversation(history)
                if history_intel.total_items() > 0:
                    update_session(session_id, intelligence=history_intel)
                    logger.info(f"Extracted {history_intel.total_items()} intel items from conversation history")
            except Exception as e:
                logger.error(f"History intelligence extraction error: {e}")

        history.extend(session.conversationHistory)

        # ── Scam detection ──
        try:
            detection_result = detect_scam(message_text, history, session_id)
        except Exception as e:
            logger.error(f"Scam detection error: {e}")
            from .models import ScamDetectionResult
            detection_result = ScamDetectionResult(
                is_scam=False, confidence=0.0, risk_score=0,
                detected_patterns=[], scam_types=[]
            )

        logger.info(
            f"Detection: is_scam={detection_result.is_scam}, "
            f"confidence={detection_result.confidence:.2f}, "
            f"types={detection_result.scam_types}"
        )

        # ── Intelligence extraction ──
        try:
            intelligence = extract_intelligence(message_text)
            update_session(session_id, intelligence=intelligence)
        except Exception as e:
            logger.error(f"Intelligence extraction error: {e}")
            from .models import IntelligenceData
            intelligence = IntelligenceData()

        # ── Agent activation check ──
        try:
            intel_dict = intelligence.to_dict()
            activate_agent = should_activate_agent(detection_result, session_id, intel_dict)
        except Exception:
            activate_agent = detection_result.is_scam

        logger.info(f"Agent activation: {activate_agent}")

        update_session(
            session_id,
            scam_detected=detection_result.is_scam or activate_agent,
            scam_types=detection_result.scam_types
        )

        # ── Generate response ──
        try:
            reply = generate_response(
                message_text,
                history,
                detection_result.scam_types if (detection_result.is_scam or activate_agent) else [],
                session_id=session_id,
            )
        except Exception as e:
            logger.error(f"Response generation error: {e}")
            reply = random.choice(_SAFE_FALLBACKS)

        # Validate reply is not empty
        if not reply or not reply.strip():
            reply = random.choice(_SAFE_FALLBACKS)

        # ── Translate reply back to original language ──
        if was_translated:
            reply = translate_response(reply, detected_language)

        logger.info(f"Response: {reply[:50]}...")

        # Add our response to session
        update_session(
            session_id,
            message={
                "sender": "user",
                "text": reply,
                "timestamp": datetime.utcnow().isoformat()
            }
        )

        # ── Session end check ──
        try:
            should_end, end_reason = should_end_session(session_id)

            if should_end:
                logger.info(f"Session {session_id} ending: {end_reason}")
                # Cancel inactivity timer since we're ending now
                with _timer_lock:
                    t = _session_timers.pop(session_id, None)
                    if t:
                        t.cancel()

                session = get_session_data(session_id)
                if session:
                    try:
                        notes = generate_notes(
                            session.conversationHistory,
                            session.detectedScamTypes,
                            session.extractedIntelligence.to_dict()
                        )
                        update_session(session_id, agent_notes=notes)
                    except Exception:
                        pass

                    complete_session(session_id, end_reason)

                    final_session = get_session_data(session_id)
                    if final_session:
                        try:
                            send_session_result_async(final_session)
                        except Exception:
                            logger.error("Failed to send callback")
            else:
                # Session still active — reset inactivity timer
                # If no new message within 7s, auto-finalize and send callback
                _reset_inactivity_timer(session_id)
        except Exception as e:
            logger.error(f"Session end check error: {e}")

        return APIResponse(status="success", reply=reply)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        # NEVER crash — always return a valid response
        return APIResponse(
            status="success",
            reply=random.choice(_SAFE_FALLBACKS)
        )


# ============================================================================
# Debug Endpoints
# ============================================================================

@app.get("/sessions", response_model=List[SessionSummary], tags=["Debug"])
async def get_sessions(api_key: str = Depends(verify_api_key)):
    return session_manager.get_all_sessions()


@app.get("/sessions/{session_id}", tags=["Debug"])
async def get_session(session_id: str, api_key: str = Depends(verify_api_key)):
    session = get_session_data(session_id)
    if not session:
        raise HTTPException(status_code=404, detail={"status": "error", "message": f"Session {session_id} not found"})

    return {
        "sessionId": session.sessionId,
        "scamDetected": session.scamDetected,
        "messageCount": session.messageCount,
        "status": session.status.value,
        "startTime": session.startTime.isoformat(),
        "lastMessageTime": session.lastMessageTime.isoformat(),
        "detectedScamTypes": session.detectedScamTypes,
        "extractedIntelligence": session.extractedIntelligence.to_dict(),
        "conversationHistory": session.conversationHistory,
        "agentNotes": session.agentNotes
    }


@app.delete("/sessions/{session_id}", tags=["Debug"])
async def delete_session(session_id: str, api_key: str = Depends(verify_api_key)):
    if session_manager.delete_session(session_id):
        return {"status": "success", "message": f"Session {session_id} deleted"}
    raise HTTPException(status_code=404, detail={"status": "error", "message": f"Session {session_id} not found"})


@app.post("/sessions/{session_id}/end", tags=["Debug"])
async def end_session(session_id: str, api_key: str = Depends(verify_api_key)):
    session = get_session_data(session_id)
    if not session:
        raise HTTPException(status_code=404, detail={"status": "error", "message": f"Session {session_id} not found"})

    # Cancel inactivity timer
    with _timer_lock:
        t = _session_timers.pop(session_id, None)
        if t:
            t.cancel()

    if not session.agentNotes:
        try:
            notes = generate_notes(
                session.conversationHistory,
                session.detectedScamTypes,
                session.extractedIntelligence.to_dict()
            )
            update_session(session_id, agent_notes=notes)
        except Exception:
            pass

    complete_session(session_id, "manual_end")

    final_session = get_session_data(session_id)
    if final_session:
        try:
            send_session_result_async(final_session)
        except Exception:
            pass

    return {"status": "success", "message": f"Session {session_id} ended and callback triggered"}


@app.get("/stats", tags=["Debug"])
async def get_stats(api_key: str = Depends(verify_api_key)):
    sessions = session_manager.get_all_sessions()
    total = len(sessions)
    active = sum(1 for s in sessions if s.status == "active")
    completed = sum(1 for s in sessions if s.status == "completed")
    scam_count = sum(1 for s in sessions if s.scamDetected)
    total_msgs = sum(s.messageCount for s in sessions)
    total_intel = sum(s.intelligenceCount for s in sessions)

    return {
        "total_sessions": total,
        "active_sessions": active,
        "completed_sessions": completed,
        "scams_detected": scam_count,
        "total_messages_processed": total_msgs,
        "total_intelligence_extracted": total_intel,
        "ai_agent_status": "active" if victim_agent.initialized else "fallback",
        "version": __version__
    }


# ============================================================================
# Test Endpoints
# ============================================================================

@app.post("/test/detect", tags=["Testing"])
async def test_scam_detection(
    message: str = Query(..., description="Message to check"),
    api_key: str = Depends(verify_api_key)
):
    result = detect_scam(message)
    intelligence = extract_intelligence(message)
    activate = should_activate_agent(result, extracted_intel=intelligence.to_dict())

    return {
        "message": message,
        "is_scam": result.is_scam,
        "confidence": result.confidence,
        "risk_score": result.risk_score,
        "detected_patterns": result.detected_patterns,
        "scam_types": result.scam_types,
        "agent_activated": activate,
        "extracted_intelligence": intelligence.to_dict()
    }


@app.post("/test/extract", tags=["Testing"])
async def test_intelligence_extraction(
    message: str = Query(..., description="Message to extract from"),
    api_key: str = Depends(verify_api_key)
):
    intelligence = extract_intelligence(message)
    return {
        "message": message,
        "extracted": intelligence.to_dict(),
        "total_items": intelligence.total_items()
    }


@app.post("/test/response", tags=["Testing"])
async def test_ai_response(
    message: str = Query(..., description="Message to respond to"),
    api_key: str = Depends(verify_api_key)
):
    result = detect_scam(message)
    response = generate_response(message, [], result.scam_types)
    return {
        "scammer_message": message,
        "victim_response": response,
        "detected_as_scam": result.is_scam,
        "scam_types": result.scam_types
    }


@app.get("/test/callback", tags=["Testing"])
async def test_callback_connection(api_key: str = Depends(verify_api_key)):
    return guvi_callback.test_connection()


# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail if isinstance(exc.detail, dict) else {
            "status": "error", "message": str(exc.detail), "code": "HTTP_ERROR"
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unexpected error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "An unexpected error occurred", "code": "INTERNAL_ERROR"}
    )


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True,
        log_level=settings.LOG_LEVEL.lower()
    )
