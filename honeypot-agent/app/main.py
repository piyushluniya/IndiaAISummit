"""
Main FastAPI Application for the Honeypot Scam Detection System.
Provides REST API endpoints for processing scammer messages and managing sessions.
"""

import time
from datetime import datetime
from typing import List, Optional
from contextlib import asynccontextmanager

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header, Request, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
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
from .scam_detector import detect_scam, scam_detector
from .ai_agent import generate_response, generate_notes, victim_agent
from .intelligence_extractor import extract_intelligence
from .session_manager import (
    session_manager,
    get_or_create_session,
    update_session,
    should_end_session,
    complete_session,
    get_session_data
)
from .guvi_callback import send_session_result_async, guvi_callback


# Lifespan context manager for startup/shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events."""
    # Startup
    logger.info("=" * 50)
    logger.info("Honeypot Scam Detection System Starting...")
    logger.info(f"Version: {__version__}")
    logger.info(f"Port: {settings.PORT}")
    logger.info(f"Gemini API configured: {bool(settings.GEMINI_API_KEY)}")
    logger.info("=" * 50)

    yield

    # Shutdown
    logger.info("Shutting down Honeypot System...")
    # Cleanup any remaining sessions
    active_count = session_manager.get_active_sessions_count()
    if active_count > 0:
        logger.warning(f"Shutting down with {active_count} active sessions")


# Initialize FastAPI application
app = FastAPI(
    title="Honeypot Scam Detection API",
    description="AI-powered honeypot system for detecting and engaging scammers to extract intelligence.",
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for web UI
STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add processing time to response headers."""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(round(process_time * 1000, 2)) + "ms"
    return response


# Logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests."""
    logger.info(f"Request: {request.method} {request.url.path}")
    response = await call_next(request)
    logger.info(f"Response: {response.status_code}")
    return response


# Authentication dependency
async def verify_api_key(x_api_key: Optional[str] = Header(None)):
    """Verify the API key from request header."""
    if not x_api_key:
        logger.warning("Request missing API key")
        raise HTTPException(
            status_code=401,
            detail={
                "status": "error",
                "message": "Missing API key. Include 'x-api-key' header.",
                "code": "AUTH_MISSING"
            }
        )

    if x_api_key != settings.API_SECRET_KEY:
        logger.warning(f"Invalid API key attempted")
        raise HTTPException(
            status_code=403,
            detail={
                "status": "error",
                "message": "Invalid API key",
                "code": "AUTH_INVALID"
            }
        )

    return x_api_key


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/", response_model=HealthCheckResponse, tags=["Health"])
async def health_check():
    """
    Health check endpoint.
    Returns system status and active session count.
    """
    return HealthCheckResponse(
        status="healthy",
        version=__version__,
        timestamp=datetime.utcnow(),
        active_sessions=session_manager.get_active_sessions_count()
    )


@app.get("/health", response_model=HealthCheckResponse, tags=["Health"])
async def health():
    """Alias for health check endpoint."""
    return await health_check()


@app.get("/ui", response_class=HTMLResponse, tags=["UI"])
async def web_ui():
    """
    Serve the interactive web UI for testing the honeypot.
    """
    html_file = STATIC_DIR / "index.html"
    if html_file.exists():
        return HTMLResponse(content=html_file.read_text(), status_code=200)
    else:
        return HTMLResponse(content="<h1>UI not found</h1>", status_code=404)


@app.post("/analyze", response_model=APIResponse, tags=["Analysis"])
async def analyze_message(
    request: IncomingMessage,
    api_key: str = Depends(verify_api_key)
):
    """
    Main endpoint for analyzing scammer messages.

    This endpoint:
    1. Receives a message from the GUVI platform
    2. Detects if it's a scam
    3. Generates an appropriate victim response
    4. Extracts intelligence from the scammer's message
    5. Manages session state
    6. Triggers GUVI callback when session ends

    Returns:
        APIResponse with status and AI-generated reply
    """
    try:
        session_id = request.sessionId
        message_text = request.message.text
        sender = request.message.sender

        logger.info(f"Processing message for session {session_id}: {message_text[:50]}...")

        # Get or create session
        session = get_or_create_session(
            session_id,
            metadata=request.metadata.model_dump() if request.metadata else {}
        )

        # Add scammer's message to session history
        update_session(
            session_id,
            message={
                "sender": sender,
                "text": message_text,
                "timestamp": request.message.timestamp or datetime.utcnow().isoformat()
            }
        )

        # Build conversation history for context
        history = []
        if request.conversationHistory:
            for msg in request.conversationHistory:
                history.append({
                    "sender": msg.sender,
                    "text": msg.text,
                    "timestamp": msg.timestamp
                })
        # Add current session history
        history.extend(session.conversationHistory)

        # Detect if message is a scam
        detection_result = detect_scam(message_text, history)

        logger.info(
            f"Scam detection: is_scam={detection_result.is_scam}, "
            f"confidence={detection_result.confidence:.2f}, "
            f"types={detection_result.scam_types}"
        )

        # Update session with scam detection
        update_session(
            session_id,
            scam_detected=detection_result.is_scam,
            scam_types=detection_result.scam_types
        )

        # Generate appropriate response
        if detection_result.is_scam:
            # Extract intelligence from scammer's message
            intelligence = extract_intelligence(message_text)

            # Update session with extracted intelligence
            update_session(session_id, intelligence=intelligence)

            # Generate AI victim response
            reply = generate_response(
                message_text,
                history,
                detection_result.scam_types
            )

            logger.info(f"Generated victim response: {reply[:50]}...")

        else:
            # Not detected as scam - send generic polite response
            reply = _get_generic_response(message_text)
            logger.info("Message not detected as scam, sending generic response")

        # Add our response to session
        update_session(
            session_id,
            message={
                "sender": "user",
                "text": reply,
                "timestamp": datetime.utcnow().isoformat()
            }
        )

        # Check if session should end
        should_end, end_reason = should_end_session(session_id)

        if should_end:
            logger.info(f"Session {session_id} ending: {end_reason}")

            # Get updated session data
            session = get_session_data(session_id)

            if session:
                # Generate agent notes
                notes = generate_notes(
                    session.conversationHistory,
                    session.detectedScamTypes,
                    session.extractedIntelligence.to_dict()
                )
                update_session(session_id, agent_notes=notes)

                # Mark session as completed
                complete_session(session_id, end_reason)

                # Get final session state and send callback
                final_session = get_session_data(session_id)
                if final_session:
                    send_session_result_async(final_session)
                    logger.info(f"GUVI callback queued for session {session_id}")

        return APIResponse(
            status="success",
            reply=reply
        )

    except Exception as e:
        logger.error(f"Error processing message: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail={
                "status": "error",
                "message": "Internal server error processing message",
                "code": "PROCESSING_ERROR"
            }
        )


@app.get("/sessions", response_model=List[SessionSummary], tags=["Debug"])
async def get_sessions(api_key: str = Depends(verify_api_key)):
    """
    Get all active sessions (debug endpoint).
    Returns summary information for all sessions.
    """
    return session_manager.get_all_sessions()


@app.get("/sessions/{session_id}", tags=["Debug"])
async def get_session(session_id: str, api_key: str = Depends(verify_api_key)):
    """
    Get detailed information for a specific session.
    """
    session = get_session_data(session_id)
    if not session:
        raise HTTPException(
            status_code=404,
            detail={
                "status": "error",
                "message": f"Session {session_id} not found",
                "code": "SESSION_NOT_FOUND"
            }
        )

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
    """
    Delete a specific session.
    """
    if session_manager.delete_session(session_id):
        return {"status": "success", "message": f"Session {session_id} deleted"}
    else:
        raise HTTPException(
            status_code=404,
            detail={
                "status": "error",
                "message": f"Session {session_id} not found",
                "code": "SESSION_NOT_FOUND"
            }
        )


@app.post("/sessions/{session_id}/end", tags=["Debug"])
async def end_session(session_id: str, api_key: str = Depends(verify_api_key)):
    """
    Manually end a session and trigger GUVI callback.
    """
    session = get_session_data(session_id)
    if not session:
        raise HTTPException(
            status_code=404,
            detail={
                "status": "error",
                "message": f"Session {session_id} not found",
                "code": "SESSION_NOT_FOUND"
            }
        )

    # Generate notes if not already present
    if not session.agentNotes:
        notes = generate_notes(
            session.conversationHistory,
            session.detectedScamTypes,
            session.extractedIntelligence.to_dict()
        )
        update_session(session_id, agent_notes=notes)

    # Mark as completed
    complete_session(session_id, "manual_end")

    # Get final session and send callback
    final_session = get_session_data(session_id)
    if final_session:
        send_session_result_async(final_session)

    return {
        "status": "success",
        "message": f"Session {session_id} ended and callback triggered"
    }


@app.get("/stats", tags=["Debug"])
async def get_stats(api_key: str = Depends(verify_api_key)):
    """
    Get system statistics.
    """
    sessions = session_manager.get_all_sessions()

    total_sessions = len(sessions)
    active_sessions = sum(1 for s in sessions if s.status == "active")
    completed_sessions = sum(1 for s in sessions if s.status == "completed")
    scam_detected_count = sum(1 for s in sessions if s.scamDetected)
    total_messages = sum(s.messageCount for s in sessions)
    total_intelligence = sum(s.intelligenceCount for s in sessions)

    return {
        "total_sessions": total_sessions,
        "active_sessions": active_sessions,
        "completed_sessions": completed_sessions,
        "scams_detected": scam_detected_count,
        "total_messages_processed": total_messages,
        "total_intelligence_extracted": total_intelligence,
        "ai_agent_status": "active" if victim_agent.initialized else "fallback",
        "version": __version__
    }


@app.post("/test/detect", tags=["Testing"])
async def test_scam_detection(
    message: str = Query(..., description="Message to check for scam"),
    api_key: str = Depends(verify_api_key)
):
    """
    Test endpoint to check scam detection for a message.
    """
    result = detect_scam(message)
    keywords = scam_detector.get_detected_keywords(message)

    return {
        "message": message,
        "is_scam": result.is_scam,
        "confidence": result.confidence,
        "risk_score": result.risk_score,
        "detected_patterns": result.detected_patterns,
        "scam_types": result.scam_types,
        "keywords_found": keywords
    }


@app.post("/test/extract", tags=["Testing"])
async def test_intelligence_extraction(
    message: str = Query(..., description="Message to extract intelligence from"),
    api_key: str = Depends(verify_api_key)
):
    """
    Test endpoint to check intelligence extraction for a message.
    """
    intelligence = extract_intelligence(message)

    return {
        "message": message,
        "extracted": intelligence.to_dict(),
        "total_items": intelligence.total_items()
    }


@app.post("/test/response", tags=["Testing"])
async def test_ai_response(
    message: str = Query(..., description="Message to generate response for"),
    api_key: str = Depends(verify_api_key)
):
    """
    Test endpoint to generate AI victim response.
    """
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
    """
    Test connection to GUVI callback endpoint.
    """
    return guvi_callback.test_connection()


# ============================================================================
# Helper Functions
# ============================================================================

def _get_generic_response(message: str) -> str:
    """
    Generate a generic polite response for non-scam messages.

    Args:
        message: The incoming message

    Returns:
        Generic response string
    """
    message_lower = message.lower()

    # Greeting responses
    if any(word in message_lower for word in ["hello", "hi", "hey", "good morning", "good evening"]):
        return "Hello! How can I help you today?"

    # Question responses
    if "?" in message:
        return "I'm not sure I understand. Could you please explain more?"

    # Default response
    return "Thank you for your message. Is there something specific you need help with?"


# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with consistent format."""
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail if isinstance(exc.detail, dict) else {
            "status": "error",
            "message": str(exc.detail),
            "code": "HTTP_ERROR"
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.error(f"Unexpected error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": "An unexpected error occurred",
            "code": "INTERNAL_ERROR"
        }
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
