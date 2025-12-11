# Cloud Resource Monitoring & Alerting System

A scalable, cloud-native solution for proactive monitoring and alerting of cloud resources. Enables early detection and resolution of performance, reliability, and security issues through automated metric collection, alerting, visualization, and audit logging.

---

## Features

- **Automated Resource Onboarding:** New cloud resources are automatically included in monitoring and alerting coverage.
- **Metrics Collection:** Collects CPU, memory, network, and storage metrics from AWS, Azure, and on-prem resources.
- **Centralized Dashboard:** Visualizes metrics, alerts, incidents, and audit trails in a modern React dashboard.
- **Alerting:** Triggers alerts when resource thresholds are exceeded and delivers notifications via email, Slack, and Alertmanager.
- **Security & Compliance:** Generates and logs security alerts for unauthorized access or configuration changes.
- **Audit Trail:** Maintains a secure, tamper-proof log of alert generation and resolution.
- **DevOps Notifications:** Notifies teams of misconfigurations or lack of monitoring coverage.
- **Cloud-Native Integrations:** Leverages Prometheus, Grafana, AWS CloudWatch, Azure Monitor, and Terraform.

---

## Architecture Overview

- **Backend:** Python 3.11, FastAPI, SQLAlchemy, PostgreSQL
- **Frontend:** React 18, TypeScript, Material-UI, Chart.js
- **Monitoring:** Prometheus (metrics), Grafana (visualization), AWS CloudWatch, Azure Monitor
- **Alerting:** Alertmanager, Slack API, SMTP (email)
- **Automation:** Terraform (resource onboarding), Docker (containerization), GitHub Actions (CI/CD)
- **Audit Logging:** PostgreSQL (secure, tamper-proof)

---

## Directory Structure

```
backend/
  main.py
  models.py
  monitoring.py
  alerting.py
  audit.py
  resource_onboarding.py
  config.yaml
  Dockerfile
  tests/
frontend/
  dashboard/
    ... (React app)
infra/
  terraform/
    ... (Terraform scripts)
README.md
```

---

## Getting Started

### Prerequisites

- Docker (for containerized deployment)
- Python 3.11+ (for backend development)
- Node.js 18+ and npm (for frontend)
- Terraform 1.5+ (for infrastructure provisioning)
- PostgreSQL 13+ (for persistent storage)

---

### 1. Infrastructure Provisioning

Provision cloud resources and monitoring stack using Terraform:

```bash
cd infra/terraform
terraform init
terraform apply
```

- Configure `variables.tf` for your AWS/Azure credentials and regions.
- Outputs will provide Prometheus and Grafana endpoints.

---

### 2. Backend Setup

#### Local Development

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
# Set environment variables as needed (DATABASE_URL, PROMETHEUS_URL, etc.)
uvicorn main:app --reload
```

#### Docker Deployment

```bash
cd backend
docker build -t cloud-monitoring-backend .
docker run -d -p 8000:8000 --env-file .env cloud-monitoring-backend
```

- Edit `backend/config.yaml` for thresholds, alert channels, and resource definitions.

---

### 3. Frontend Setup

```bash
cd frontend/dashboard
npm install
npm start
```

- Set `REACT_APP_API_BASE` in `.env` if backend is not at `http://localhost:8000`.

---

### 4. Configuration

- **Thresholds, alert channels, and resource definitions:** `backend/config.yaml`
- **Environment variables:** Use `.env` files or export variables for secrets and endpoints.

---

### 5. Running Tests

Backend tests:

```bash
cd backend
pytest tests/
```

Frontend tests:

```bash
cd frontend/dashboard
npm test
```

---

## Operational Procedures

- **Onboarding New Resources:** Use the API or dashboard to add resources; Terraform can automate provisioning and onboarding.
- **Alert Management:** View and resolve alerts via dashboard or API.
- **Incident & Audit Logging:** All alert and incident actions are logged for compliance.
- **Security Events:** Security-relevant events are logged and visualized in the dashboard.
- **DevOps Notifications:** Misconfigurations or missing monitoring coverage trigger notifications to DevOps via Slack/email.

---

## Security & Compliance

- **Audit logs** are stored in PostgreSQL with retention and encryption options.
- **Monitoring configuration** is reviewed for completeness and security coverage.
- **Credentials and secrets** should be managed securely (e.g., environment variables, secret managers).
- **Network access** to monitoring endpoints should be restricted.

---

## Extending the System

- Add support for additional cloud providers by extending `monitoring.py` and Terraform modules.
- Add new alert channels by extending `alerting.py`.
- Integrate with other incident management or ticketing systems as needed.

---

## Documentation

- API documentation available at `/docs` (FastAPI Swagger UI).
- See `backend/config.yaml` and `infra/terraform/README.md` for configuration details.

---

## License

MIT

---

## Authors

Cloud Resource Monitoring & Alerting System Engineering Team