import logging
from typing import Optional, Dict, Any

from sqlalchemy.orm import Session

from models import Resource, ResourceCreate, ResourceRead

# Configure logging
logger = logging.getLogger("resource_onboarding")
logger.setLevel(logging.INFO)

def onboard_new_resource(resource_data: ResourceCreate, db: Session) -> ResourceRead:
    """
    Onboard a new cloud resource for monitoring.

    Args:
        resource_data (ResourceCreate): Resource creation data.
        db (Session): SQLAlchemy session.

    Returns:
        ResourceRead: The onboarded resource.
    """
    try:
        # Check if resource already exists
        existing = db.query(Resource).filter(Resource.name == resource_data.name).first()
        if existing:
            if not existing.onboarded:
                existing.onboarded = True
                db.commit()
                db.refresh(existing)
                logger.info(f"Resource {existing.name} re-onboarded.")
                return ResourceRead.from_orm(existing)
            else:
                logger.warning(f"Resource {existing.name} already onboarded.")
                return ResourceRead.from_orm(existing)
        # Create new resource
        new_resource = Resource(
            name=resource_data.name,
            type=resource_data.type,
            cloud_provider=resource_data.cloud_provider,
            region=resource_data.region,
            metadata=resource_data.metadata,
            onboarded=True,
        )
        db.add(new_resource)
        db.commit()
        db.refresh(new_resource)
        logger.info(f"Resource {new_resource.name} onboarded for monitoring.")
        # Optionally: trigger monitoring setup (e.g., Prometheus scrape config, CloudWatch/Azure setup)
        return ResourceRead.from_orm(new_resource)
    except Exception as e:
        logger.error(f"Failed to onboard resource: {e}", exc_info=True)
        db.rollback()
        raise

def get_onboarding_status(db: Session) -> Dict[str, Any]:
    """
    Get status of resource onboarding automation.

    Args:
        db (Session): SQLAlchemy session.

    Returns:
        Dict[str, Any]: Onboarding status summary.
    """
    try:
        total = db.query(Resource).count()
        onboarded = db.query(Resource).filter(Resource.onboarded == True).count()
        not_onboarded = total - onboarded
        return {
            "total_resources": total,
            "onboarded": onboarded,
            "not_onboarded": not_onboarded,
            "status": "ok" if onboarded == total else "pending",
        }
    except Exception as e:
        logger.error(f"Failed to get onboarding status: {e}", exc_info=True)
        raise

__all__ = [
    "onboard_new_resource",
    "get_onboarding_status",
]