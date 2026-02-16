"""
Session Management Module for the Honeypot System.
Manages conversation sessions, tracks state, and handles session lifecycle.
"""

import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from .models import SessionData, IntelligenceData, SessionStatus, SessionSummary
from .config import logger, settings


class SessionManager:
    """
    In-memory session storage and management.
    Thread-safe implementation for concurrent access.
    """

    def __init__(self):
        """Initialize the session manager."""
        self._sessions: Dict[str, SessionData] = {}
        self._lock = threading.RLock()
        logger.info("SessionManager initialized")

    def create_session(
        self,
        session_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SessionData:
        """
        Create a new session or return existing one.

        Args:
            session_id: Unique session identifier
            metadata: Optional metadata for the session

        Returns:
            SessionData object
        """
        with self._lock:
            if session_id in self._sessions:
                logger.debug(f"Session {session_id} already exists")
                return self._sessions[session_id]

            session = SessionData(
                sessionId=session_id,
                scamDetected=False,
                messageCount=0,
                startTime=datetime.utcnow(),
                lastMessageTime=datetime.utcnow(),
                conversationHistory=[],
                extractedIntelligence=IntelligenceData(),
                agentNotes="",
                status=SessionStatus.ACTIVE,
                detectedScamTypes=[],
                metadata=metadata or {}
            )

            self._sessions[session_id] = session
            logger.info(f"Created new session: {session_id}")
            return session

    def get_session(self, session_id: str) -> Optional[SessionData]:
        """
        Get a session by ID.

        Args:
            session_id: Session identifier

        Returns:
            SessionData or None if not found
        """
        with self._lock:
            return self._sessions.get(session_id)

    def update_session(
        self,
        session_id: str,
        scam_detected: Optional[bool] = None,
        scam_types: Optional[List[str]] = None,
        message: Optional[Dict[str, str]] = None,
        intelligence: Optional[IntelligenceData] = None,
        agent_notes: Optional[str] = None
    ) -> Optional[SessionData]:
        """
        Update session with new data.

        Args:
            session_id: Session identifier
            scam_detected: Whether scam was detected
            scam_types: Types of scams detected
            message: New message to add to history
            intelligence: New intelligence to merge
            agent_notes: Notes to update

        Returns:
            Updated SessionData or None
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                logger.warning(f"Session {session_id} not found for update")
                return None

            # Update scam detection status
            if scam_detected is not None:
                session.scamDetected = session.scamDetected or scam_detected

            # Update scam types
            if scam_types:
                existing_types = set(session.detectedScamTypes)
                existing_types.update(scam_types)
                session.detectedScamTypes = list(existing_types)

            # Add message to history
            if message:
                session.conversationHistory.append(message)
                session.messageCount = len(session.conversationHistory)

            # Merge intelligence
            if intelligence:
                session.extractedIntelligence.merge(intelligence)

            # Update notes
            if agent_notes:
                session.agentNotes = agent_notes

            # Update last message time
            session.lastMessageTime = datetime.utcnow()

            logger.debug(
                f"Updated session {session_id}: messages={session.messageCount}, "
                f"scam={session.scamDetected}"
            )
            return session

    def add_message(
        self,
        session_id: str,
        sender: str,
        text: str,
        timestamp: Optional[str] = None
    ) -> bool:
        """
        Add a message to session history.

        Args:
            session_id: Session identifier
            sender: Message sender (scammer/user)
            text: Message text
            timestamp: Optional ISO timestamp

        Returns:
            True if successful
        """
        message = {
            "sender": sender,
            "text": text,
            "timestamp": timestamp or datetime.utcnow().isoformat()
        }
        result = self.update_session(session_id, message=message)
        return result is not None

    def should_end_session(self, session_id: str) -> tuple[bool, str]:
        """
        Check if a session should be ended.

        Args:
            session_id: Session identifier

        Returns:
            Tuple of (should_end, reason)
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return True, "session_not_found"

            # Check if already completed
            if session.status == SessionStatus.COMPLETED:
                return True, "already_completed"

            # Check message count limit
            if session.messageCount >= settings.MAX_MESSAGES_PER_SESSION:
                return True, "max_messages_reached"

            # Check session duration
            session_duration = datetime.utcnow() - session.startTime
            if session_duration > timedelta(minutes=settings.SESSION_TIMEOUT_MINUTES):
                return True, "session_timeout"

            # Check inactivity timeout
            inactivity = datetime.utcnow() - session.lastMessageTime
            if inactivity > timedelta(minutes=settings.SESSION_INACTIVITY_TIMEOUT_MINUTES):
                return True, "inactivity_timeout"

            # Check if sufficient intelligence extracted
            intel = session.extractedIntelligence
            intel_count = intel.total_items()
            if intel_count >= settings.MIN_INTELLIGENCE_FOR_END * 2 and session.messageCount >= 10:
                return True, "sufficient_intelligence"

            return False, ""

    def mark_completed(self, session_id: str, reason: str = "") -> Optional[SessionData]:
        """
        Mark a session as completed.

        Args:
            session_id: Session identifier
            reason: Reason for completion

        Returns:
            Updated SessionData or None
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None

            session.status = SessionStatus.COMPLETED

            # Add completion note
            if reason:
                completion_note = f" Session ended: {reason}."
                session.agentNotes = (session.agentNotes + completion_note).strip()

            logger.info(f"Session {session_id} marked as completed: {reason}")
            return session

    def get_session_summary(self, session_id: str) -> Optional[SessionSummary]:
        """
        Get a summary of a session.

        Args:
            session_id: Session identifier

        Returns:
            SessionSummary or None
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None

            return SessionSummary(
                sessionId=session.sessionId,
                scamDetected=session.scamDetected,
                messageCount=session.messageCount,
                status=session.status.value,
                startTime=session.startTime,
                lastMessageTime=session.lastMessageTime,
                intelligenceCount=session.extractedIntelligence.total_items()
            )

    def get_all_sessions(self) -> List[SessionSummary]:
        """
        Get summaries of all sessions.

        Returns:
            List of SessionSummary objects
        """
        with self._lock:
            summaries = []
            for session_id in self._sessions:
                summary = self.get_session_summary(session_id)
                if summary:
                    summaries.append(summary)
            return summaries

    def get_active_sessions_count(self) -> int:
        """Get count of active sessions."""
        with self._lock:
            return sum(
                1 for s in self._sessions.values()
                if s.status == SessionStatus.ACTIVE
            )

    def cleanup_old_sessions(self, max_age_hours: int = 24) -> int:
        """
        Remove sessions older than specified age.

        Args:
            max_age_hours: Maximum age in hours

        Returns:
            Number of sessions removed
        """
        with self._lock:
            cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
            old_sessions = [
                sid for sid, session in self._sessions.items()
                if session.startTime < cutoff and session.status == SessionStatus.COMPLETED
            ]

            for sid in old_sessions:
                del self._sessions[sid]

            if old_sessions:
                logger.info(f"Cleaned up {len(old_sessions)} old sessions")

            return len(old_sessions)

    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session.

        Args:
            session_id: Session identifier

        Returns:
            True if deleted, False if not found
        """
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                logger.info(f"Deleted session: {session_id}")
                return True
            return False

    def get_session_for_callback(self, session_id: str) -> Optional[Dict]:
        """
        Get session data formatted for GUVI callback.

        Args:
            session_id: Session identifier

        Returns:
            Dictionary formatted for callback payload
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None

            duration = (session.lastMessageTime - session.startTime).total_seconds()

            return {
                "sessionId": session.sessionId,
                "scamDetected": session.scamDetected,
                "totalMessagesExchanged": session.messageCount,
                "extractedIntelligence": session.extractedIntelligence.to_dict(),
                "engagementDurationSeconds": max(duration, 0),
                "agentNotes": session.agentNotes
            }


# Singleton instance
session_manager = SessionManager()


# Convenience functions
def get_or_create_session(session_id: str, metadata: Dict = None) -> SessionData:
    """Get existing session or create new one."""
    session = session_manager.get_session(session_id)
    if session:
        return session
    return session_manager.create_session(session_id, metadata)


def update_session(session_id: str, **kwargs) -> Optional[SessionData]:
    """Update a session with new data."""
    return session_manager.update_session(session_id, **kwargs)


def should_end_session(session_id: str) -> tuple[bool, str]:
    """Check if session should be ended."""
    return session_manager.should_end_session(session_id)


def complete_session(session_id: str, reason: str = "") -> Optional[SessionData]:
    """Mark session as completed."""
    return session_manager.mark_completed(session_id, reason)


def get_session_data(session_id: str) -> Optional[SessionData]:
    """Get session data."""
    return session_manager.get_session(session_id)
