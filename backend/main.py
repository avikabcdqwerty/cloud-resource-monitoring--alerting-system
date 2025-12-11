import logging
import os
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR

from models import (
    Base,
    get_db,
    Resource,
    Alert,
    Incident,
    AuditLog,
    ResourceCreate,
    ResourceRead,
    AlertRead,
    IncidentRead,
    AuditLogRead,
)
from monitoring import (
    fetch_resource_metrics,
    get_all_monitored_resources,
    get_resource_metrics,
)
from alerting import (
    check_alerts_for_resource,
    get_active_alerts,
    resolve_alert,
    AlertStatusUpdate,
    send_test_alert,
)
from audit import (
    log_audit_event,
    get_audit_logs,
)
from resource_onboarding import (
    onboard_new_resource,
    get_onboarding_status,
)
import uvicorn

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("cloud-monitoring-api")

# FastAPI app initialization
app = FastAPI(
    title="Cloud Resource Monitoring & Alerting API",
    description="API for monitoring, alerting, and auditing cloud resources.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration (adjust origins as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception handlers
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error."},
    )

# Health check endpoint
@app.get("/health", tags=["Health"])
def health_check():
    """
    Health check endpoint for readiness/liveness probes.
    """
    return {"status": "ok"}

# ------------------- Resource Endpoints -------------------

@app.get("/resources", response_model=List[ResourceRead], tags=["Resources"])
def list_resources(db: Session = Depends(get_db)):
    """
    List all monitored cloud resources.
    """
    resources = get_all_monitored_resources(db)
    return resources

@app.post("/resources", response_model=ResourceRead, status_code=status.HTTP_201_CREATED, tags=["Resources"])
def create_resource(resource: ResourceCreate, db: Session = Depends(get_db)):
    """
    Onboard a new cloud resource for monitoring.
    """
    try:
        new_resource = onboard_new_resource(resource, db)
        log_audit_event(
            db=db,
            event_type="resource_onboarded",
            details=f"Resource {new_resource.name} onboarded.",
        )
        return new_resource
    except Exception as e:
        logger.error(f"Failed to onboard resource: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/resources/{resource_id}/metrics", tags=["Metrics"])
def get_metrics_for_resource(resource_id: int, db: Session = Depends(get_db)):
    """
    Fetch latest metrics for a specific resource.
    """
    try:
        metrics = get_resource_metrics(resource_id, db)
        return metrics
    except Exception as e:
        logger.error(f"Failed to fetch metrics for resource {resource_id}: {e}", exc_info=True)
        raise HTTPException(status_code=404, detail="Resource or metrics not found.")

# ------------------- Alerting Endpoints -------------------

@app.get("/alerts", response_model=List[AlertRead], tags=["Alerts"])
def list_active_alerts(db: Session = Depends(get_db)):
    """
    List all active alerts.
    """
    return get_active_alerts(db)

@app.post("/alerts/check/{resource_id}", tags=["Alerts"])
def check_alerts(resource_id: int, db: Session = Depends(get_db)):
    """
    Manually trigger alert check for a resource.
    """
    try:
        triggered_alerts = check_alerts_for_resource(resource_id, db)
        return {"triggered_alerts": triggered_alerts}
    except Exception as e:
        logger.error(f"Alert check failed for resource {resource_id}: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))

@app.patch("/alerts/{alert_id}/resolve", tags=["Alerts"])
def resolve_alert_endpoint(alert_id: int, status_update: AlertStatusUpdate, db: Session = Depends(get_db)):
    """
    Resolve an alert and log the incident resolution.
    """
    try:
        resolved_alert = resolve_alert(alert_id, status_update, db)
        log_audit_event(
            db=db,
            event_type="alert_resolved",
            details=f"Alert {alert_id} resolved. Status: {status_update.status}",
        )
        return resolved_alert
    except Exception as e:
        logger.error(f"Failed to resolve alert {alert_id}: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/alerts/test", tags=["Alerts"])
def send_test_alert_endpoint(channel: Optional[str] = "email"):
    """
    Send a test alert to verify alerting integrations.
    """
    try:
        send_test_alert(channel)
        return {"detail": f"Test alert sent via {channel}."}
    except Exception as e:
        logger.error(f"Failed to send test alert: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))

# ------------------- Incident Endpoints -------------------

@app.get("/incidents", response_model=List[IncidentRead], tags=["Incidents"])
def list_incidents(db: Session = Depends(get_db)):
    """
    List all incidents (resolved and unresolved).
    """
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).all()
    return incidents

# ------------------- Audit Trail Endpoints -------------------

@app.get("/audit", response_model=List[AuditLogRead], tags=["Audit"])
def get_audit_trail(limit: int = 100, db: Session = Depends(get_db)):
    """
    Retrieve audit logs for alert generation and resolution.
    """
    return get_audit_logs(db, limit=limit)

# ------------------- Resource Onboarding Status -------------------

@app.get("/onboarding/status", tags=["Resources"])
def onboarding_status(db: Session = Depends(get_db)):
    """
    Get status of resource onboarding automation.
    """
    return get_onboarding_status(db)

# ------------------- Security Events Endpoint -------------------

@app.post("/security/event", tags=["Security"])
def log_security_event(event: dict, db: Session = Depends(get_db)):
    """
    Log a security-relevant event (e.g., unauthorized access, config change).
    """
    try:
        log_audit_event(
            db=db,
            event_type="security_event",
            details=str(event),
        )
        return {"detail": "Security event logged."}
    except Exception as e:
        logger.error(f"Failed to log security event: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))

# ------------------- Misconfiguration Notification -------------------

@app.post("/notify/devops", tags=["Notifications"])
def notify_devops(issue: dict):
    """
    Notify DevOps team of misconfigurations or lack of monitoring coverage.
    """
    # This would typically integrate with Slack/email in alerting.py
    try:
        from alerting import notify_devops_team
        notify_devops_team(issue)
        return {"detail": "DevOps notified."}
    except Exception as e:
        logger.error(f"Failed to notify DevOps: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))

# ------------------- Startup Event -------------------

@app.on_event("startup")
def on_startup():
    """
    Startup tasks: Ensure DB schema, log startup, etc.
    """
    from sqlalchemy import create_engine
    from sqlalchemy_utils import database_exists, create_database

    db_url = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/monitoring")
    engine = create_engine(db_url)
    if not database_exists(engine.url):
        create_database(engine.url)
    Base.metadata.create_all(bind=engine)
    logger.info("Cloud Resource Monitoring & Alerting API started.")

# ------------------- Main Entrypoint -------------------

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=bool(os.getenv("DEBUG", False)),
        log_level="info",
    )