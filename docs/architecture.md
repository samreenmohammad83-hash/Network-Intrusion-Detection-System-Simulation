# Architecture

## Components

1. **Synthetic Traffic Generator** — creates flow records only.
2. **Flow Collector** — FastAPI receives JSON flow records.
3. **Feature Extractor** — validates fields and derives rates/ratios.
4. **Rule Engine** — configurable signature rules.
5. **Anomaly Detector** — baseline/deviation scoring.
6. **ML Layer** — optional supervised and unsupervised models.
7. **Risk Engine** — weighted hybrid score.
8. **Alert Engine** — normalized SOC alerts.
9. **Correlation** — groups repeated related alerts.
10. **SQLite** — stores flows, alerts, rules, and notes.
11. **React Dashboard** — KPIs, charts, alert queue, investigation.
12. **Analyst** — triage, notes, status changes.

## Data flow

```text
Synthetic Record
   |
   v
Pydantic Validation
   |
   v
Feature Extraction
   |
   +--> Rule Engine
   |
   +--> Anomaly Engine
   |
   +--> Optional ML
   |
   v
Risk Engine
   |
   v
Alert Engine
   |
   v
SQLite
   |
   v
React SOC Dashboard
```

## Why hybrid?

Rules are explainable and fast. Anomaly detection provides behavioral context. ML can provide an additional learned signal. The system combines these signals while keeping the rule/anomaly evidence visible to an analyst.
