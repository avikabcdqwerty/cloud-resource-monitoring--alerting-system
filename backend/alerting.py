import os
import logging
from typing import List, Dict, Any, Optional

from sqlalchemy.orm import Session

from models import (
    Resource,
    Alert,
    Incident,
    AuditLog,
    AlertSeverity,
    AlertStatus,
    IncidentStatus,
    AlertRead,
    AlertStatusUpdate,
)

from monitoring import fetch_resource_metrics

import smtplib
from email.mime.text import MIMEText
import requests

# Slack and Alertmanager configuration
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
ALERTMANAGER_URL = os.getenv("ALERTMANAGER_URL", "http://alertmanager:9093/api/v1/alerts")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.example.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "alert@example.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "password")
ALERT_EMAIL_RECIPIENTS = os.getenv("ALERT_EMAIL_RECIPIENTS", "devops@example.com").split(",")

# Thresholds (should be loaded from config.yaml in production)
DEFAULT_THRESHOLDS = {
    "cpu": 80,      # percent
    "memory": 80,   # percent
    "network": 1000000000,  # bytes/sec
    "storage": 90,  # percent used
}

# Configure logging
logger = logging.getLogger("alerting")
logger.setLevel(logging.INFO)

# ------------------- Alert Rule Logic -------------------

def evaluate_thresholds(metrics: Dict[str, Any], thresholds: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluate metrics against thresholds and return list of violations.
    """
    violations = []
    # CPU threshold
    cpu_metric = metrics.get("cpu")
    if cpu_metric:
        cpu_value = extract_metric_value(cpu_metric)
        if cpu_value is not None and cpu_value > thresholds.get("cpu", 80):
            violations.append({
                "metric": "cpu",
                "value": cpu_value,
                "threshold": thresholds.get("cpu", 80),
                "message": f"CPU usage {cpu_value}% exceeds threshold {thresholds.get('cpu', 80)}%",
            })
    # Memory threshold
    mem_metric = metrics.get("memory")
    if mem_metric:
        mem_value = extract_metric_value(mem_metric)
        if mem_value is not None and mem_value > thresholds.get("memory", 80):
            violations.append({
                "metric": "memory",
                "value": mem_value,
                "threshold": thresholds.get("memory", 80),
                "message": f"Memory usage {mem_value}% exceeds threshold {thresholds.get('memory', 80)}%",
            })
    # Network threshold
    net_metric = metrics.get("network")
    if net_metric:
        net_value = extract_metric_value(net_metric)
        if net_value is not None and net_value > thresholds.get("network", 1000000000):
            violations.append({
                "metric": "network",
                "value": net_value,
                "threshold": thresholds.get("network", 1000000000),
                "message": f"Network throughput {net_value} bytes/sec exceeds threshold {thresholds.get('network', 1000000000)} bytes/sec",
            })
    # Storage threshold
    storage_metric = metrics.get("storage")
    if storage_metric:
        storage_value = extract_metric_value(storage_metric)
        if storage_value is not None and storage_value > thresholds.get("storage", 90):
            violations.append({
                "metric": "storage",
                "value": storage_value,
                "threshold": thresholds.get("storage", 90),
                "message": f"Storage usage {storage_value}% exceeds threshold {thresholds.get('storage', 90)}%",
            })
    return violations

def extract_metric_value(metric_data: Any) -> Optional[float]:
    """
    Extract numeric value from Prometheus/CloudWatch/Azure metric result.
    """
    # Prometheus: list of dicts with 'value' key
    if isinstance(metric_data, list) and metric_data:
        try:
            # Prometheus format: [ { 'value': [timestamp, value] }, ... ]
            value = float(metric_data[0]['value'][1])
            return value
        except Exception:
            return None
    # CloudWatch/Azure: list of dicts with 'Average' or 'Value'
    if isinstance(metric_data, list) and metric_data:
        try:
            value = float(metric_data[0].get('Average') or metric_data[0].get('Value'))
            return value
        except Exception:
            return None
    return None

# ------------------- Alert Creation & Delivery -------------------

def create_alert(resource: Resource, violation: Dict[str, Any], db: Session, channel: str = "email") -> Alert:
    """
    Create and persist an alert, then deliver via specified channel.
    """
    alert = Alert(
        resource_id=resource.id,
        severity=AlertSeverity.CRITICAL,
        status=AlertStatus.ACTIVE,
        message=violation["message"],
        details=violation,
        channel=channel,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    # Deliver alert
    deliver_alert(alert, resource, channel)
    logger.info(f"Alert created for resource {resource.name}: {violation['message']}")
    return alert

def deliver_alert(alert: Alert, resource: Resource, channel: str):
    """
    Deliver alert via specified channel (email, Slack, Alertmanager).
    """
    try:
        if channel == "email":
            send_email_alert(alert, resource)
        elif channel == "slack":
            send_slack_alert(alert, resource)
        elif channel == "alertmanager":
            send_alertmanager_alert(alert, resource)
        else:
            logger.warning(f"Unknown alert channel: {channel}")
    except Exception as e:
        logger.error(f"Failed to deliver alert {alert.id} via {channel}: {e}", exc_info=True)

def send_email_alert(alert: Alert, resource: Resource):
    """
    Send alert via SMTP email.
    """
    subject = f"[ALERT] {resource.name}: {alert.message}"
    body = f"""
    Alert for resource: {resource.name}
    Severity: {alert.severity}
    Message: {alert.message}
    Details: {alert.details}
    """
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_USERNAME
    msg["To"] = ", ".join(ALERT_EMAIL_RECIPIENTS)
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_USERNAME, ALERT_EMAIL_RECIPIENTS, msg.as_string())
        logger.info(f"Email alert sent for alert {alert.id}")
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}", exc_info=True)

def send_slack_alert(alert: Alert, resource: Resource):
    """
    Send alert to Slack via webhook.
    """
    if not SLACK_WEBHOOK_URL:
        logger.warning("SLACK_WEBHOOK_URL not configured.")
        return
    payload = {
        "text": f":rotating_light: *ALERT* for resource `{resource.name}`\n*Severity*: {alert.severity}\n*Message*: {alert.message}\n*Details*: {alert.details}"
    }
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        response.raise_for_status()
        logger.info(f"Slack alert sent for alert {alert.id}")
    except Exception as e:
        logger.error(f"Failed to send Slack alert: {e}", exc_info=True)

def send_alertmanager_alert(alert: Alert, resource: Resource):
    """
    Send alert to Alertmanager via API.
    """
    payload = [{
        "labels": {
            "alertname": "ResourceThresholdExceeded",
            "severity": alert.severity.value,
            "resource": resource.name,
            "metric": alert.details.get("metric"),
        },
        "annotations": {
            "description": alert.message,
            "details": str(alert.details),
        },
        "startsAt": alert.triggered_at.isoformat() + "Z",
    }]
    try:
        response = requests.post(ALERTMANAGER_URL, json=payload, timeout=5)
        response.raise_for_status()
        logger.info(f"Alertmanager alert sent for alert {alert.id}")
    except Exception as e:
        logger.error(f"Failed to send Alertmanager alert: {e}", exc_info=True)

# ------------------- Alert Evaluation & Triggering -------------------

def check_alerts_for_resource(resource_id: int, db: Session) -> List[Dict[str, Any]]:
    """
    Evaluate metrics for a resource and trigger alerts if thresholds are exceeded.
    """
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    if not resource or not resource.onboarded:
        raise ValueError("Resource not found or not onboarded.")
    metrics = fetch_resource_metrics(resource)
    violations = evaluate_thresholds(metrics, DEFAULT_THRESHOLDS)
    triggered_alerts = []
    for violation in violations:
        alert = create_alert(resource, violation, db)
        triggered_alerts.append(AlertRead.from_orm(alert))
    return triggered_alerts

def get_active_alerts(db: Session) -> List[AlertRead]:
    """
    Retrieve all active alerts.
    """
    alerts = db.query(Alert).filter(Alert.status == AlertStatus.ACTIVE).order_by(Alert.triggered_at.desc()).all()
    return [AlertRead.from_orm(a) for a in alerts]

def resolve_alert(alert_id: int, status_update: AlertStatusUpdate, db: Session) -> AlertRead:
    """
    Resolve an alert and log incident resolution.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise ValueError("Alert not found.")
    alert.status = status_update.status
    alert.resolved_at = status_update.resolved_at
    db.commit()
    # Log incident
    incident = Incident(
        alert_id=alert.id,
        resource_id=alert.resource_id,
        status=IncidentStatus.CLOSED if status_update.status == AlertStatus.RESOLVED else IncidentStatus.IN_PROGRESS,
        description=f"Alert {alert.id} resolved by {status_update.resolver}",
        created_at=alert.triggered_at,
        resolved_at=status_update.resolved_at,
        resolver=status_update.resolver,
    )
    db.add(incident)
    db.commit()
    logger.info(f"Alert {alert.id} resolved and incident logged.")
    return AlertRead.from_orm(alert)

# ------------------- Test Alert Endpoint -------------------

def send_test_alert(channel: str = "email"):
    """
    Send a test alert to verify alerting integrations.
    """
    dummy_alert = Alert(
        id=0,
        resource_id=None,
        severity=AlertSeverity.INFO,
        status=AlertStatus.ACTIVE,
        message="Test alert: This is a test notification.",
        details={"test": True},
        channel=channel,
    )
    dummy_resource = Resource(
        id=0,
        name="test-resource",
        type="other",
        cloud_provider="test",
        region="test",
        metadata={},
        onboarded=True,
    )
    deliver_alert(dummy_alert, dummy_resource, channel)

# ------------------- DevOps Notification -------------------

def notify_devops_team(issue: Dict[str, Any]):
    """
    Notify DevOps team of misconfigurations or lack of monitoring coverage.
    """
    message = f":warning: *DevOps Notification*\nIssue: {issue.get('description', 'Unknown')}\nDetails: {issue}"
    if SLACK_WEBHOOK_URL:
        try:
            response = requests.post(SLACK_WEBHOOK_URL, json={"text": message}, timeout=5)
            response.raise_for_status()
            logger.info("DevOps team notified via Slack.")
        except Exception as e:
            logger.error(f"Failed to notify DevOps via Slack: {e}", exc_info=True)
    else:
        # Fallback to email
        try:
            msg = MIMEText(message)
            msg["Subject"] = "DevOps Notification"
            msg["From"] = SMTP_USERNAME
            msg["To"] = ", ".join(ALERT_EMAIL_RECIPIENTS)
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
                server.sendmail(SMTP_USERNAME, ALERT_EMAIL_RECIPIENTS, msg.as_string())
            logger.info("DevOps team notified via email.")
        except Exception as e:
            logger.error(f"Failed to notify DevOps via email: {e}", exc_info=True)

# ------------------- EXPORTS -------------------

__all__ = [
    "check_alerts_for_resource",
    "get_active_alerts",
    "resolve_alert",
    "AlertStatusUpdate",
    "send_test_alert",
    "notify_devops_team",
]