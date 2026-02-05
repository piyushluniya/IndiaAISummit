"""
Pydantic models for the Honeypot Scam Detection System.
Defines request/response schemas and data structures.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class SenderType(str, Enum):
    """Enum for message sender types."""
    SCAMMER = "scammer"
    USER = "user"
    VICTIM = "victim"


class SessionStatus(str, Enum):
    """Enum for session status."""
    ACTIVE = "active"
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    ERROR = "error"


class MessageData(BaseModel):
    """Schema for a single message."""
    sender: str = Field(..., description="Message sender (scammer or user)")
    text: str = Field(..., description="Message content")
    timestamp: Optional[str] = Field(None, description="ISO 8601 timestamp")

    class Config:
        json_schema_extra = {
            "example": {
                "sender": "scammer",
                "text": "Your bank account will be blocked today.",
                "timestamp": "2026-01-21T10:15:30Z"
            }
        }


class Metadata(BaseModel):
    """Schema for request metadata."""
    channel: Optional[str] = Field("SMS", description="Communication channel")
    language: Optional[str] = Field("English", description="Message language")
    locale: Optional[str] = Field("IN", description="Locale/region code")

    class Config:
        json_schema_extra = {
            "example": {
                "channel": "SMS",
                "language": "English",
                "locale": "IN"
            }
        }


class IncomingMessage(BaseModel):
    """Schema for incoming API request from GUVI platform."""
    sessionId: Optional[str] = Field(None, description="Unique session identifier")
    message: Optional[Any] = Field(None, description="Current message - can be string or MessageData object")
    conversationHistory: Optional[List[MessageData]] = Field(
        default_factory=list,
        description="Previous messages in conversation"
    )
    metadata: Optional[Metadata] = Field(
        default_factory=Metadata,
        description="Additional metadata"
    )
    # Alternative field names GUVI might use
    session_id: Optional[str] = Field(None, description="Alternative session ID field")
    text: Optional[str] = Field(None, description="Direct text field")
    msg: Optional[str] = Field(None, description="Alternative message field")

    def get_session_id(self) -> str:
        """Get session ID from various possible field names."""
        return self.sessionId or self.session_id or "default-session"

    def get_message_text(self) -> str:
        """Get message text from various possible formats."""
        # If message is a string directly
        if isinstance(self.message, str):
            return self.message
        # If message is a dict/MessageData object
        if isinstance(self.message, dict):
            return self.message.get("text", self.message.get("content", ""))
        if hasattr(self.message, "text"):
            return self.message.text
        # Try alternative fields
        if self.text:
            return self.text
        if self.msg:
            return self.msg
        return ""

    def get_sender(self) -> str:
        """Get sender from message."""
        if isinstance(self.message, dict):
            return self.message.get("sender", "scammer")
        if hasattr(self.message, "sender"):
            return self.message.sender
        return "scammer"

    class Config:
        json_schema_extra = {
            "example": {
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
        }


class APIResponse(BaseModel):
    """Schema for API response to GUVI platform."""
    status: str = Field("success", description="Response status")
    reply: str = Field(..., description="AI-generated victim response")

    class Config:
        json_schema_extra = {
            "example": {
                "status": "success",
                "reply": "Oh no! Why is my account being blocked? What should I do?"
            }
        }


class ErrorResponse(BaseModel):
    """Schema for error responses."""
    status: str = Field("error", description="Error status")
    message: str = Field(..., description="Error message")
    code: Optional[str] = Field(None, description="Error code")

    class Config:
        json_schema_extra = {
            "example": {
                "status": "error",
                "message": "Invalid API key",
                "code": "AUTH_FAILED"
            }
        }


class IntelligenceData(BaseModel):
    """Schema for extracted intelligence from scammer messages."""
    phoneNumbers: List[str] = Field(default_factory=list, description="Extracted phone numbers")
    upiIds: List[str] = Field(default_factory=list, description="Extracted UPI IDs")
    bankAccounts: List[str] = Field(default_factory=list, description="Extracted bank account numbers")
    phishingLinks: List[str] = Field(default_factory=list, description="Extracted URLs/links")
    suspiciousKeywords: List[str] = Field(default_factory=list, description="Detected suspicious keywords")

    def total_items(self) -> int:
        """Return total number of extracted intelligence items."""
        return (
            len(self.phoneNumbers) +
            len(self.upiIds) +
            len(self.bankAccounts) +
            len(self.phishingLinks)
        )

    def merge(self, other: 'IntelligenceData') -> 'IntelligenceData':
        """Merge another intelligence data object into this one."""
        self.phoneNumbers = list(set(self.phoneNumbers + other.phoneNumbers))
        self.upiIds = list(set(self.upiIds + other.upiIds))
        self.bankAccounts = list(set(self.bankAccounts + other.bankAccounts))
        self.phishingLinks = list(set(self.phishingLinks + other.phishingLinks))
        self.suspiciousKeywords = list(set(self.suspiciousKeywords + other.suspiciousKeywords))
        return self

    def to_dict(self) -> Dict[str, List[str]]:
        """Convert to dictionary format."""
        return {
            "phoneNumbers": self.phoneNumbers,
            "upiIds": self.upiIds,
            "bankAccounts": self.bankAccounts,
            "phishingLinks": self.phishingLinks,
            "suspiciousKeywords": self.suspiciousKeywords
        }


class ScamDetectionResult(BaseModel):
    """Schema for scam detection results."""
    is_scam: bool = Field(..., description="Whether message is identified as scam")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score (0-1)")
    risk_score: int = Field(..., ge=0, description="Numerical risk score")
    detected_patterns: List[str] = Field(default_factory=list, description="List of detected scam patterns")
    scam_types: List[str] = Field(default_factory=list, description="Types of scam detected")

    class Config:
        json_schema_extra = {
            "example": {
                "is_scam": True,
                "confidence": 0.95,
                "risk_score": 45,
                "detected_patterns": ["bank_fraud", "urgency"],
                "scam_types": ["bank_fraud", "phishing"]
            }
        }


class SessionData(BaseModel):
    """Schema for session data storage."""
    sessionId: str = Field(..., description="Unique session identifier")
    scamDetected: bool = Field(False, description="Whether scam has been detected")
    messageCount: int = Field(0, description="Total messages exchanged")
    startTime: datetime = Field(default_factory=datetime.utcnow, description="Session start time")
    lastMessageTime: datetime = Field(default_factory=datetime.utcnow, description="Last message timestamp")
    conversationHistory: List[Dict[str, str]] = Field(
        default_factory=list,
        description="Full conversation history"
    )
    extractedIntelligence: IntelligenceData = Field(
        default_factory=IntelligenceData,
        description="Extracted intelligence data"
    )
    agentNotes: str = Field("", description="Notes generated by AI agent")
    status: SessionStatus = Field(SessionStatus.ACTIVE, description="Session status")
    detectedScamTypes: List[str] = Field(default_factory=list, description="Types of scams detected")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Session metadata")

    class Config:
        json_schema_extra = {
            "example": {
                "sessionId": "abc123",
                "scamDetected": True,
                "messageCount": 5,
                "startTime": "2026-01-21T10:00:00Z",
                "lastMessageTime": "2026-01-21T10:15:00Z",
                "conversationHistory": [],
                "extractedIntelligence": {
                    "phoneNumbers": ["9876543210"],
                    "upiIds": ["scammer@paytm"],
                    "bankAccounts": [],
                    "phishingLinks": [],
                    "suspiciousKeywords": ["blocked", "verify"]
                },
                "agentNotes": "Scammer attempting bank fraud via UPI",
                "status": "active",
                "detectedScamTypes": ["bank_fraud", "upi_fraud"],
                "metadata": {}
            }
        }


class GuviCallbackPayload(BaseModel):
    """Schema for final callback to GUVI platform."""
    sessionId: str = Field(..., description="Session identifier")
    scamDetected: bool = Field(..., description="Whether scam was detected")
    totalMessagesExchanged: int = Field(..., description="Total messages in conversation")
    extractedIntelligence: Dict[str, List[str]] = Field(
        ...,
        description="All extracted intelligence"
    )
    agentNotes: str = Field(..., description="Summary notes from AI agent")

    class Config:
        json_schema_extra = {
            "example": {
                "sessionId": "abc123",
                "scamDetected": True,
                "totalMessagesExchanged": 20,
                "extractedIntelligence": {
                    "bankAccounts": [],
                    "upiIds": ["scammer@paytm"],
                    "phishingLinks": [],
                    "phoneNumbers": ["9876543210"],
                    "suspiciousKeywords": ["blocked", "verify", "urgent"]
                },
                "agentNotes": "Scammer attempted bank fraud via UPI. Extracted phone number and UPI ID."
            }
        }


class HealthCheckResponse(BaseModel):
    """Schema for health check endpoint response."""
    status: str = Field("healthy", description="Service health status")
    version: str = Field(..., description="API version")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Current timestamp")
    active_sessions: int = Field(0, description="Number of active sessions")

    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "version": "1.0.0",
                "timestamp": "2026-01-21T10:00:00Z",
                "active_sessions": 5
            }
        }


class SessionSummary(BaseModel):
    """Schema for session summary (used in debug endpoints)."""
    sessionId: str
    scamDetected: bool
    messageCount: int
    status: str
    startTime: datetime
    lastMessageTime: datetime
    intelligenceCount: int

    class Config:
        json_schema_extra = {
            "example": {
                "sessionId": "abc123",
                "scamDetected": True,
                "messageCount": 10,
                "status": "active",
                "startTime": "2026-01-21T10:00:00Z",
                "lastMessageTime": "2026-01-21T10:15:00Z",
                "intelligenceCount": 3
            }
        }
