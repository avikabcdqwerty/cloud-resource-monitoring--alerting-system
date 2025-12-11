import logging
from typing import Optional, List

from sqlalchemy.orm import Session

from models import AuditLog, AuditEventType, AuditLogRead

# Configure logging
logger = logging.getLogger("audit")
logger.setLevel(logging.INFO)

def log_audit_event(
    db: Session,
    event_type: str,
    details: Optional[str] = None,
    actor: Optional[str] = None,
) -> AuditLog:
    """
    Log an audit event for alert generation, resolution, resource onboarding, or security events.

    Args:
        db (Session): SQLAlchemy session.
        event_type (str): Type of event (AuditEventType).
        details (Optional[str]): Event details.
        actor (Optional[str]): User/service responsible.

    Returns:
        AuditLog: The created audit log entry.
    """
    try:
        audit_entry = AuditLog(
            event_type=AuditEventType(event_type),
            details=details,
            actor=actor,
        )
        db.add(audit_entry)
        db.commit()
        db.refresh(audit_entry)
        logger.info(f"Audit event logged: {event_type} - {details}")
        return audit_entry
    except Exception as e:
        logger.error(f"Failed to log audit event: {e}", exc_info=True)
        db.rollback()
        raise

def get_audit_logs(db: Session, limit: int = 100) -> List[AuditLogRead]:
    """
    Retrieve recent audit logs.

    Args:
        db (Session): SQLAlchemy session.
        limit (int): Number of logs to retrieve.

    Returns:
        List[AuditLogRead]: List of audit log entries.
    """
    try:
        logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
        return [AuditLogRead.from_orm(log) for log in logs]
    except Exception as e:
        logger.error(f"Failed to retrieve audit logs: {e}", exc_info=True)
        raise

__all__ = [
    "log_audit_event",
    "get_audit_logs",
]