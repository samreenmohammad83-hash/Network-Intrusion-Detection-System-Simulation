# Network Intrusion Detection System (IDS) Simulation

A defensive, industry-oriented Network IDS simulation built entirely around **synthetic network-flow records**. It combines configurable signature rules, statistical anomaly detection, optional machine learning, risk scoring, alert correlation, incident investigation, a REST API, and a SOC-style React dashboard.

> **Safety:** This project never scans, probes, exploits, floods, or sends attack traffic. Suspicious behavior exists only as synthetic data records or local application events.

## Overview

The project simulates the workflow:

`Synthetic Traffic -> Feature Extraction -> Rules + Anomaly + Optional ML -> Risk Score -> Alert -> SQLite -> SOC Dashboard`

## Objectives

- Generate 5,000+ synthetic network-flow records.
- Detect configurable suspicious patterns.
- Combine signature and anomaly detection.
- Train/evaluate optional supervised and unsupervised ML models.
- Generate and correlate SOC-style alerts.
- Investigate alerts and manage incident status.
- Expose a beginner-friendly REST API.
- Provide a professional dashboard suitable for a course project and GitHub proof of work.

## Technology Stack

- Python 3.11+
- FastAPI + Pydantic
- SQLite
- Pandas / NumPy
- scikit-learn + joblib
- React + Vite + Recharts
- Pytest

## Dataset

`simulator/generate_dataset.py` creates `data/network_traffic.csv` with 5,000 records by default. It uses documentation/reserved IP ranges such as `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.

Scenarios include:

- NORMAL_WEB
- NORMAL_DNS
- NORMAL_SSH
- NORMAL_EMAIL
- NORMAL_DATABASE
- HIGH_CONNECTION_RATE
- REPEATED_FAILED_CONNECTIONS
- MULTI_PORT_PROBING_PATTERN
- SYN_HEAVY_PATTERN
- UNUSUAL_PORT_ACTIVITY
- HIGH_TRAFFIC_VOLUME

The suspicious scenarios are **records**, not packets.

## Detection

### Signature rules

- IDS-001 High Connection Rate
- IDS-002 Repeated Failed Connections
- IDS-003 Destination Port Diversity
- IDS-004 SYN-Heavy Behavior
- IDS-005 Unusual Service-Port Activity
- IDS-006 High Traffic Volume

A rule match indicates behavior requiring investigation; it does not by itself prove malicious activity.

### Anomaly detection

The anomaly engine calculates a 0–100 score from deviation against a baseline using z-score style normalization. It evaluates packet rate, byte rate, connection rate, failure ratio, and destination-port diversity.

### Optional ML

`ml/train_model.py` evaluates:

- Logistic Regression
- Random Forest
- Isolation Forest

Metrics are calculated from the generated dataset; no results are hard-coded.

## Risk scoring

With ML enabled:

- Rules: 40%
- Anomaly: 30%
- ML: 30%

Without ML:

- Rules: 60%
- Anomaly: 40%

Classification thresholds are project assumptions and should be calibrated against real SOC data.

## Architecture

```text
Synthetic Traffic Generator
          |
          v
      Flow Collector
          |
          v
    Feature Extractor
       /    |    \
      v     v     v
   Rules  Anomaly  ML
      \     |     /
       \    |    /
          Risk Engine
              |
         Alert Engine
              |
          SQLite DB
              |
        FastAPI REST API
              |
        React SOC Dashboard
              |
           Analyst
```

## Folder Structure

```text
Network-Intrusion-Detection-System-Simulation/
├── simulator/
│   ├── traffic_simulator.py
│   └── generate_dataset.py
├── ids/
│   ├── feature_extractor.py
│   ├── rule_engine.py
│   ├── anomaly_detector.py
│   ├── risk_engine.py
│   ├── alert_engine.py
│   └── correlation.py
├── ml/
│   ├── train_model.py
│   ├── predict.py
│   └── evaluate.py
├── backend/
│   ├── app.py
│   ├── db.py
│   ├── schemas.py
│   └── services/
│       └── detection_service.py
├── frontend/
│   ├── package.json
│   └── src/
│       ├── App.jsx
│       ├── main.jsx
│       └── styles.css
├── data/
├── models/
├── tests/
├── screenshots/
├── docs/
├── reports/
├── requirements.txt
├── .env.example
└── .gitignore
```

## Installation — Windows PowerShell

```powershell
cd Network-Intrusion-Detection-System-Simulation
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If `py` is not available:

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

## Step 1 — Generate dataset

```powershell
python simulator/generate_dataset.py --records 5000 --output data/network_traffic.csv
```

## Step 2 — Train/evaluate ML

```powershell
python ml/train_model.py --data data/network_traffic.csv
python ml/evaluate.py --data data/network_traffic.csv
```

## Step 3 — Start backend

From the project root:

```powershell
uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000/docs
```

## Step 4 — Start React dashboard

Open a second PowerShell:

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL shown by the terminal, normally:

```text
http://localhost:5173
```

## Step 5 — Start synthetic simulator

Open a third PowerShell:

```powershell
cd Network-Intrusion-Detection-System-Simulation
.\.venv\Scripts\Activate.ps1
python simulator/traffic_simulator.py --mode mixed --speed slow --api-url http://127.0.0.1:8000
```

The simulator posts only JSON flow records to your own local FastAPI application. It does not transmit packets.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/flows` | Analyze and store one synthetic flow |
| GET | `/api/flows` | List flow records |
| GET | `/api/flows/{id}` | Get one flow |
| GET | `/api/alerts` | List alerts |
| GET | `/api/alerts/{id}` | Get alert details |
| PUT | `/api/alerts/{id}/status` | Update alert status |
| POST | `/api/alerts/{id}/notes` | Add analyst note |
| GET | `/api/dashboard/stats` | KPI statistics |
| GET | `/api/dashboard/traffic` | Time-series data |
| GET | `/api/dashboard/alerts` | Alert chart data |
| GET | `/api/rules` | Detection rules |
| PUT | `/api/rules/{id}` | Enable/update rule threshold |

## Safe investigation workflow

1. Open an alert.
2. Review source/destination and protocol/ports.
3. Compare traffic features with baseline.
4. Review matched rule and anomaly score.
5. If ML is enabled, review the model score.
6. Review related local application records/logs.
7. Check whether the source is known and expected.
8. Add an analyst note.
9. Change `NEW -> INVESTIGATING`.
10. Resolve as `RESOLVED` or `FALSE_POSITIVE`.

## False positives and false negatives

A false positive is legitimate behavior incorrectly flagged. A false negative is suspicious behavior missed by the detector. Better baselines, threshold tuning, multiple detection methods, context, and analyst feedback can improve the system.

## Security

- Synthetic/reserved-address data only.
- No packet payload storage.
- Environment variables for secrets/configuration.
- CORS restricted to the local frontend by default.
- Validation for IPs, ports, protocol, and numeric fields.
- Least-privilege design.
- Audit-friendly incident notes.
- Production deployments should use TLS, authentication, authorization, rate limiting, secure log storage, and a hardened database.

IDS data can itself be sensitive because source/destination metadata, timing, service information, and analyst notes can reveal internal architecture and user activity.

## MITRE ATT&CK

ATT&CK mapping should be added only when the observed evidence supports a technique. A statistical anomaly alone should not automatically be mapped to an ATT&CK technique. In a real SOC, the mapping would be based on corroborating telemetry and documented analytic logic.

## SIEM integration

The API can be adapted to forward normalized JSON alerts to a SIEM:

```json
{
  "alert_id": "ALT-1001",
  "source_ip": "192.0.2.15",
  "destination_ip": "198.51.100.20",
  "severity": "HIGH",
  "rule": "High Connection Rate",
  "risk_score": 78
}
```

Conceptually:

`IDS -> JSON Alert -> Log Forwarder/API -> SIEM -> Correlation -> SOC Analyst`

## Testing

Run:

```powershell
pytest -q
```

The test suite covers normal traffic, suspicious patterns, validation, feature extraction, anomaly/risk scoring, alerts, correlation, database storage, API validation, ML prediction, and duplicate handling.

## Screenshot checklist

Capture:

1. Folder structure
2. Architecture diagram
3. Generated dataset
4. Normal synthetic flow
5. Suspicious synthetic flow
6. Triggered rule
7. Anomaly score
8. Risk score
9. Alert
10. SOC dashboard
11. Traffic chart
12. Protocol chart
13. Severity chart
14. Investigation view
15. Analyst note
16. Incident status
17. ML evaluation
18. Confusion matrix
19. Automated tests
20. API response
21. Database records
22. GitHub commits
23. README

Suggested filenames:

```text
01_project_structure.png
02_architecture.png
03_dataset_preview.png
04_normal_flow.png
05_suspicious_flow.png
06_rule_trigger.png
07_anomaly_score.png
08_risk_score.png
09_alert_generated.png
10_soc_dashboard.png
11_traffic_timeline.png
12_protocol_distribution.png
13_severity_distribution.png
14_alert_investigation.png
15_analyst_note.png
16_incident_status.png
17_ml_evaluation.png
18_confusion_matrix.png
19_pytest_results.png
20_api_response.png
21_database_records.png
22_github_commits.png
23_readme.png
```

## GitHub

Repository name:

`Network-Intrusion-Detection-System-Simulation`

Description:

`Defensive network intrusion detection simulation featuring synthetic traffic generation, signature-based and anomaly-based detection, risk scoring, alert correlation, SOC analytics, and optional machine learning.`

Topics:

`cybersecurity intrusion-detection ids network-security soc python anomaly-detection machine-learning security-analytics threat-detection defensive-security`

Recommended commits:

```text
Initialize network IDS simulation
Add synthetic traffic dataset generator
Implement network traffic simulator
Add network feature extraction
Implement signature detection rules
Add anomaly detection engine
Implement hybrid risk scoring
Add security alert generation
Implement alert correlation
Add optional ML detection
Build SOC dashboard
Add incident investigation workflow
Implement automated tests
Complete README and documentation
```

### Git commands

```powershell
git init
git add .
git commit -m "Initialize network IDS simulation"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/Network-Intrusion-Detection-System-Simulation.git
git push -u origin main
```

Never commit `.env`, secrets, credentials, or generated model/data files if they are large.

## Resume bullets

- Built a defensive Network IDS simulation using Python and FastAPI with configurable signature rules, statistical anomaly detection, hybrid risk scoring, alert generation, and SOC-style investigation.
- Generated and analyzed 5,000+ synthetic network-flow records with feature engineering for packet rate, byte rate, connection rate, failure ratio, SYN behavior, and port diversity.
- Implemented optional Logistic Regression, Random Forest, and Isolation Forest models with measured accuracy, precision, recall, F1 score, and confusion-matrix evaluation.

## Two-line project description

Defensive Network IDS simulation that analyzes synthetic network flows using rule-based and anomaly-based detection with optional machine learning. Includes risk scoring, alert correlation, incident investigation, REST APIs, SQLite storage, and a SOC dashboard.

## LinkedIn description

Built a defensive **Network Intrusion Detection System (IDS) Simulation** to understand how SOC teams detect and investigate suspicious network-flow behavior.

The project generates synthetic network traffic and combines configurable signature-based rules, statistical anomaly detection, optional machine learning, risk scoring, alert correlation, incident status management, and a React SOC dashboard. It includes a FastAPI backend, SQLite security-event store, automated tests, and ML evaluation.

All suspicious activity is represented as synthetic records; the project does not scan, probe, exploit, or attack external systems.

## Learning outcomes

- Network security fundamentals
- Flow-based traffic analysis
- Detection engineering
- Feature engineering
- Statistical anomaly detection
- Machine learning evaluation
- Alert triage and correlation
- REST API design
- Security data visualization
- Defensive secure coding

## Ethical disclaimer

This project is designed exclusively for defensive cybersecurity education. All suspicious network behavior is represented using synthetic data or authorized isolated lab environments.
