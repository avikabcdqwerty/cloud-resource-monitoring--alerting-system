from datetime import datetime
from typing import Optional, List

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Boolean,
    ForeignKey,
    Enum,
    JSON,
    Text,
    create_engine,
)
from sqlalchemy.orm import relationship, declarative_base, sessionmaker, Session
from sqlalchemy.ext.declarative import declared_attr
from pydantic import BaseModel, Field

import enum
import os

# SQLAlchemy base
Base = declarative_base()

# ------------------- ENUMS -------------------

class ResourceType(str, enum.Enum):
    VM = "vm"
    CONTAINER = "container"
    DATABASE = "database"
    STORAGE = "storage"
    NETWORK = "network"
    OTHER = "other"

class AlertSeverity(str, enum.Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    SECURITY = "security"

class AlertStatus(str, enum.Enum):
    ACTIVE = "active"
    RESOLVED = "resolved"
    ACKNOWLEDGED = "acknowledged"

class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    CLOSED = "closed"
    IN_PROGRESS = "in_progress"

class AuditEventType(str, enum.Enum):
    ALERT_TRIGGERED = "alert_triggered"
    ALERT_RESOLVED = "alert_resolved"
    RESOURCE_ONBOARDED = "resource_onboarded"
    SECURITY_EVENT = "security_event"
    CONFIG_CHANGE = "config_change"
    INCIDENT_LOGGED = "incident_logged"
    DEVOPS_NOTIFIED = "devops_notified"

# ------------------- DATABASE MODELS -------------------

class Resource(Base):
    """
    Cloud resource model.
    """
    __tablename__ = "resources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), unique=True, nullable=False)
    type = Column(Enum(ResourceType), nullable=False)
    cloud_provider = Column(String(64), nullable=False)
    region = Column(String(64), nullable=True)
    metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    onboarded = Column(Boolean, default=False, nullable=False)

    alerts = relationship("Alert", back_populates="resource", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="resource", cascade="all, delete-orphan")

class Alert(Base):
    """
    Alert model for resource threshold violations and security events.
    """
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    resource_id = Column(Integer, ForeignKey("resources.id"), nullable=True)
    severity = Column(Enum(AlertSeverity), nullable=False)
    status = Column(Enum(AlertStatus), default=AlertStatus.ACTIVE, nullable=False)
    message = Column(String(256), nullable=False)
    details = Column(JSON, nullable=True)
    triggered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    channel = Column(String(32), nullable=True)  # e.g., email, slack

    resource = relationship("Resource", back_populates="alerts")
    incident = relationship("Incident", back_populates="alert", uselist=False)

class Incident(Base):
    """
    Incident model for tracking alert resolutions.
    """
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    resource_id = Column(Integer, ForeignKey("resources.id"), nullable=True)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    resolver = Column(String(128), nullable=True)

    alert = relationship("Alert", back_populates="incident")
    resource = relationship("Resource", back_populates="incidents")

class AuditLog(Base):
    """
    Audit log model for tracking alert generation, resolution, and security events.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(Enum(AuditEventType), nullable=False)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    actor = Column(String(128), nullable=True)  # user/service responsible

# ------------------- Pydantic SCHEMAS -------------------

class ResourceCreate(BaseModel):
    name: str = Field(..., example="prod-db-01")
    type: ResourceType = Field(..., example="database")
    cloud_provider: str = Field(..., example="aws")
    region: Optional[str] = Field(None, example="us-east-1")
    metadata: Optional[dict] = Field(None, example={"instance_type": "db.t3.medium"})

class ResourceRead(BaseModel):
    id: int
    name: str
    type: ResourceType
    cloud_provider: str
    region: Optional[str]
    metadata: Optional[dict]
    created_at: datetime
    onboarded: bool

    class Config:
        orm_mode = True

class AlertRead(BaseModel):
    id: int
    resource_id: Optional[int]
    severity: AlertSeverity
    status: AlertStatus
    message: str
    details: Optional[dict]
    triggered_at: datetime
    resolved_at: Optional[datetime]
    channel: Optional[str]

    class Config:
        orm_mode = True

class AlertStatusUpdate(BaseModel):
    status: AlertStatus = Field(..., example="resolved")
    resolved_at: Optional[datetime] = Field(default_factory=datetime.utcnow)
    resolver: Optional[str] = Field(None, example="admin")

class IncidentRead(BaseModel):
    id: int
    alert_id: int
    resource_id: Optional[int]
    status: IncidentStatus
    description: Optional[str]
    created_at: datetime
    resolved_at: Optional[datetime]
    resolver: Optional[str]

    class Config:
        orm_mode = True

class AuditLogRead(BaseModel):
    id: int
    event_type: AuditEventType
    details: Optional[str]
    created_at: datetime
    actor: Optional[str]

    class Config:
        orm_mode = True

# ------------------- DATABASE SESSION UTILS -------------------

def get_db():
    """
    Dependency for FastAPI to provide a database session.
    """
    db_url = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/monitoring")
    engine = create_engine(db_url, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ------------------- EXPORTS -------------------

__all__ = [
    "Base",
    "get_db",
    "Resource",
    "Alert",
    "Incident",
    "AuditLog",
    "ResourceCreate",
    "ResourceRead",
    "AlertRead",
    "AlertStatusUpdate",
    "IncidentRead",
    "AuditLogRead",
    "ResourceType",
    "AlertSeverity",
    "AlertStatus",
    "IncidentStatus",
    "AuditEventType",
]