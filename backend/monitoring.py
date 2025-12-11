import os
import logging
from typing import List, Dict, Any, Optional

from sqlalchemy.orm import Session

from models import Resource, ResourceRead

import requests
import boto3
from botocore.exceptions import BotoCoreError, ClientError

# Configure logging
logger = logging.getLogger("monitoring")
logger.setLevel(logging.INFO)

PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# ------------------- Prometheus Integration -------------------

def query_prometheus(query: str) -> Optional[Dict[str, Any]]:
    """
    Query Prometheus for a given metric.
    """
    try:
        response = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": query},
            timeout=5,
        )
        response.raise_for_status()
        result = response.json()
        if result.get("status") == "success":
            return result.get("data", {}).get("result", [])
        else:
            logger.warning(f"Prometheus query failed: {result}")
            return None
    except Exception as e:
        logger.error(f"Error querying Prometheus: {e}", exc_info=True)
        return None

def fetch_resource_metrics_prometheus(resource: Resource) -> Dict[str, Any]:
    """
    Fetch CPU, memory, network, and storage metrics for a resource from Prometheus.
    """
    metrics = {}
    try:
        # Example queries; adjust as needed for your Prometheus setup
        cpu_query = f'avg(rate(node_cpu_seconds_total{{instance="{resource.name}"}}[5m]))'
        mem_query = f'node_memory_MemAvailable_bytes{{instance="{resource.name}"}}'
        net_query = f'node_network_receive_bytes_total{{instance="{resource.name}"}}'
        disk_query = f'node_filesystem_avail_bytes{{instance="{resource.name}"}}'

        metrics["cpu"] = query_prometheus(cpu_query)
        metrics["memory"] = query_prometheus(mem_query)
        metrics["network"] = query_prometheus(net_query)
        metrics["storage"] = query_prometheus(disk_query)
    except Exception as e:
        logger.error(f"Failed to fetch Prometheus metrics for resource {resource.name}: {e}", exc_info=True)
    return metrics

# ------------------- AWS CloudWatch Integration -------------------

def fetch_resource_metrics_cloudwatch(resource: Resource) -> Dict[str, Any]:
    """
    Fetch metrics from AWS CloudWatch for a given resource.
    """
    metrics = {}
    try:
        client = boto3.client("cloudwatch", region_name=AWS_REGION)
        # Example: Fetch CPUUtilization for EC2 instance
        if resource.type == "vm" and resource.metadata and "instance_id" in resource.metadata:
            instance_id = resource.metadata["instance_id"]
            cpu_stats = client.get_metric_statistics(
                Namespace="AWS/EC2",
                MetricName="CPUUtilization",
                Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                StartTime=datetime.utcnow() - timedelta(minutes=10),
                EndTime=datetime.utcnow(),
                Period=300,
                Statistics=["Average"],
            )
            metrics["cpu"] = cpu_stats.get("Datapoints", [])
        # Add more metrics as needed (memory, network, storage)
    except (BotoCoreError, ClientError) as e:
        logger.error(f"CloudWatch error for resource {resource.name}: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"Failed to fetch CloudWatch metrics for resource {resource.name}: {e}", exc_info=True)
    return metrics

# ------------------- Azure Monitor Integration -------------------

def fetch_resource_metrics_azure(resource: Resource) -> Dict[str, Any]:
    """
    Fetch metrics from Azure Monitor for a given resource.
    """
    metrics = {}
    # Placeholder: Implement Azure Monitor integration as needed
    # Use azure-mgmt-monitor or REST API
    logger.info(f"Azure Monitor integration not implemented for resource {resource.name}")
    return metrics

# ------------------- Unified Metric Collection -------------------

def fetch_resource_metrics(resource: Resource) -> Dict[str, Any]:
    """
    Fetch metrics for a resource from the appropriate monitoring backend.
    """
    if resource.cloud_provider.lower() == "aws":
        return fetch_resource_metrics_cloudwatch(resource)
    elif resource.cloud_provider.lower() == "azure":
        return fetch_resource_metrics_azure(resource)
    else:
        # Default to Prometheus for on-prem or unknown providers
        return fetch_resource_metrics_prometheus(resource)

def get_resource_metrics(resource_id: int, db: Session) -> Dict[str, Any]:
    """
    Get metrics for a resource by ID.
    """
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    if not resource:
        raise ValueError("Resource not found.")
    metrics = fetch_resource_metrics(resource)
    return {
        "resource_id": resource.id,
        "name": resource.name,
        "type": resource.type,
        "metrics": metrics,
    }

def get_all_monitored_resources(db: Session) -> List[ResourceRead]:
    """
    Get all resources currently onboarded for monitoring.
    """
    resources = db.query(Resource).filter(Resource.onboarded == True).all()
    return [ResourceRead.from_orm(r) for r in resources]

# ------------------- EXPORTS -------------------

__all__ = [
    "fetch_resource_metrics",
    "get_resource_metrics",
    "get_all_monitored_resources",
]