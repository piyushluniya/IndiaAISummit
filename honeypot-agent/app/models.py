"""
Pydantic models for the Honeypot Scam Detection System.
Defines request/response schemas and data structures.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
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
    timestamp: Optional[Any] = Field(None, description="Timestamp - can be epoch ms (int) or ISO string")

    @field_validator("sender")
    @classmethod
    def validate_sender(cls, v: str) -> str:
        if not v or not v.strip():
            return "scammer"
        return v.strip().lower()

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        if not v:
            return ""
        return v.strip()[:5000]  # Truncate overly long messages

    class Config:
        json_schema_extra = {
            "example": {
                "sender": "scammer",
                "text": "Your bank account will be blocked today.",
                "timestamp": 1770005528731
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
    sessionId: str = Field(..., description="Unique session identifier")
    message: MessageData = Field(..., description="Current message from scammer")
    conversationHistory: Optional[List[MessageData]] = Field(
        default_factory=list,
        description="Previous messages in conversation"
    )
    metadata: Optional[Metadata] = Field(
        None,
        description="Additional metadata"
    )

    @field_validator("sessionId")
    @classmethod
    def validate_session_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("sessionId cannot be empty")
        return v.strip()

    def get_session_id(self) -> str:
        """Get session ID."""
        return self.sessionId

    def get_message_text(self) -> str:
        """Get message text."""
        return self.message.text

    def get_sender(self) -> str:
        """Get sender from message."""
        return self.message.sender

    def get_timestamp(self) -> str:
        """Get timestamp as ISO string."""
        if self.message.timestamp:
            # If it's a number (epoch ms), convert to ISO
            if isinstance(self.message.timestamp, (int, float)):
                from datetime import datetime
                return datetime.fromtimestamp(self.message.timestamp / 1000).isoformat()
            return str(self.message.timestamp)
        return datetime.utcnow().isoformat()

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
    emailAddresses: List[str] = Field(default_factory=list, description="Extracted email addresses")
    suspiciousKeywords: List[str] = Field(default_factory=list, description="Detected suspicious keywords")

    def total_items(self) -> int:
        """Return total number of extracted intelligence items."""
        return (
            len(self.phoneNumbers) +
            len(self.upiIds) +
            len(self.bankAccounts) +
            len(self.phishingLinks) +
            len(self.emailAddresses)
        )

    def merge(self, other: 'IntelligenceData') -> 'IntelligenceData':
        """Merge another intelligence data object into this one."""
        self.phoneNumbers = list(set(self.phoneNumbers + other.phoneNumbers))
        self.upiIds = list(set(self.upiIds + other.upiIds))
        self.bankAccounts = list(set(self.bankAccounts + other.bankAccounts))
        self.phishingLinks = list(set(self.phishingLinks + other.phishingLinks))
        self.emailAddresses = list(set(self.emailAddresses + other.emailAddresses))
        self.suspiciousKeywords = list(set(self.suspiciousKeywords + other.suspiciousKeywords))
        return self

    def to_dict(self) -> Dict[str, List[str]]:
        """Convert to dictionary format."""
        return {
            "phoneNumbers": self.phoneNumbers,
            "upiIds": self.upiIds,
            "bankAccounts": self.bankAccounts,
            "phishingLinks": self.phishingLinks,
            "emailAddresses": self.emailAddresses,
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


class EngagementMetrics(BaseModel):
    """Schema for engagement metrics in final output."""
    engagementDurationSeconds: float = Field(0, description="Duration of engagement in seconds")
    totalMessagesExchanged: int = Field(0, description="Total messages exchanged")

    class Config:
        json_schema_extra = {
            "example": {
                "engagementDurationSeconds": 120.5,
                "totalMessagesExchanged": 10
            }
        }


class GuviCallbackPayload(BaseModel):
    """Schema for final callback to GUVI platform."""
    sessionId: str = Field(..., description="Session identifier")
    status: str = Field("success", description="Status of the session")
    scamDetected: bool = Field(..., description="Whether scam was detected")
    totalMessagesExchanged: int = Field(..., description="Total messages in conversation")
    extractedIntelligence: Dict[str, List[str]] = Field(
        ...,
        description="All extracted intelligence"
    )
    engagementMetrics: EngagementMetrics = Field(
        default_factory=EngagementMetrics,
        description="Engagement quality metrics"
    )
    agentNotes: str = Field(..., description="Summary notes from AI agent")

    class Config:
        json_schema_extra = {
            "example": {
                "sessionId": "abc123",
                "status": "success",
                "scamDetected": True,
                "totalMessagesExchanged": 20,
                "extractedIntelligence": {
                    "bankAccounts": [],
                    "upiIds": ["scammer@paytm"],
                    "phishingLinks": [],
                    "phoneNumbers": ["9876543210"],
                    "emailAddresses": [],
                    "suspiciousKeywords": ["blocked", "verify", "urgent"]
                },
                "engagementMetrics": {
                    "engagementDurationSeconds": 120.5,
                    "totalMessagesExchanged": 20
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
