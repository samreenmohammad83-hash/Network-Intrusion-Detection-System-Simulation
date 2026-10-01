# Network Intrusion Detection System (IDS) Simulation — Project Report

## Abstract

This project presents a defensive Network Intrusion Detection System simulation that analyzes synthetic network-flow records without generating real attack traffic. The system extracts traffic features, applies configurable signature rules and statistical anomaly detection, optionally evaluates machine-learning models, computes a hybrid risk score, generates alerts, correlates related events, and presents security telemetry through a SOC-style dashboard.

## Introduction

Organizations monitor network behavior to identify events that may require security investigation. An IDS observes traffic or flow information and produces alerts when known signatures or abnormal behavior are detected.

## Problem Statement

A student-friendly IDS project should demonstrate practical detection engineering without requiring access to production network infrastructure or generating harmful traffic. The proposed system uses synthetic flow records to model common normal and suspicious patterns.

## Objectives

- Generate 5,000+ synthetic flow records.
- Engineer network-security features.
- Implement configurable rules.
- Implement statistical anomaly detection.
- Evaluate optional ML models.
- Generate and correlate alerts.
- Store security events.
- Provide SOC investigation workflow.
- Visualize security telemetry.

## Network Security Background

A network flow summarizes communication metadata such as source/destination, protocol, ports, bytes, packets and duration. It is less detailed than a full packet capture but useful for behavior-oriented monitoring.

## Intrusion Detection Systems

A Network IDS (NIDS) monitors network-related telemetry for indicators that may require investigation. A Host IDS (HIDS) focuses on activity on individual hosts. Signature detection looks for known patterns; anomaly detection looks for deviations from an established baseline.

## Existing Approaches

Signature-based systems are typically fast and explainable but can miss novel patterns. Anomaly-based systems can surface unusual behavior but may produce false positives. Hybrid systems combine multiple evidence sources.

## Proposed System

The project uses a hybrid NIDS simulation consisting of synthetic traffic, validation, feature extraction, rule detection, anomaly scoring, optional ML, risk scoring, alert generation, correlation, database storage, and a dashboard.

## Synthetic Dataset

The dataset contains source/destination addresses from documentation/reserved ranges, protocol, ports, packet counts, bytes, duration, connection counts, failed connections, SYN/RST counts, average packet size, labels and scenario types.

## Traffic Simulation

The simulator continuously creates JSON flow records. It does not create raw packets or send traffic to a network.

## Feature Engineering

Important features include packets per second, bytes per second, connection rate, failure ratio, SYN ratio, destination-port diversity, and destination-IP diversity.

## Signature Detection

The rule engine detects high connection rate, repeated failures, destination-port diversity, SYN-heavy behavior, unusual service ports, and high traffic volume. Thresholds are configurable.

## Anomaly Detection

A baseline is built from feature statistics. New observations are compared using deviation from baseline values and converted to a 0–100 anomaly score.

## Machine Learning

The optional ML layer evaluates Logistic Regression and Random Forest as supervised classifiers and Isolation Forest as an unsupervised detector. Metrics are calculated from an actual train/test split.

## Hybrid Detection

Rule, anomaly and optional ML signals are combined using configurable weights. With ML enabled, the default is 40/30/30; without ML, 60/40.

## Risk Scoring

Scores are normalized to 0–100 and classified into project-defined bands. These bands are assumptions for the educational simulation and require calibration in a real SOC.

## Alert Generation

Alerts include identifiers, network context, matched rule, severity, risk score, anomaly score, description and status.

## Alert Correlation

Repeated alerts from the same source and alert type within a time window are grouped to reduce analyst noise.

## Dashboard

The React dashboard presents flow counts, suspicious activity, open alerts, critical alerts, average risk, timelines, severity, protocols, alert types, and an investigation modal.

## SOC Workflow

The analyst can open an alert, inspect context, add notes, and change status from NEW to INVESTIGATING, RESOLVED, or FALSE_POSITIVE.

## Testing

The test suite contains 30 focused tests covering valid and invalid flows, detection rules, features, anomaly scoring, risk scoring, alert generation, correlation, and duplicate behavior.

## Security

The project avoids payload capture, uses synthetic data, validates inputs, isolates secrets in environment configuration, and keeps the default service local. Production deployment would require authentication, authorization, TLS, rate limiting, hardened storage and protected logs.

## Results

The generated dataset and ML metrics are produced by running the included scripts. No metric values are hard-coded in this report.

## False Positives

Legitimate traffic can resemble suspicious behavior, such as a backup causing unusually high traffic. Threshold tuning, baselines, context and analyst feedback can reduce false-positive volume.

## False Negatives

A detector can miss suspicious activity if its rules, baseline, features or model do not represent the observed behavior. Multiple detection approaches can improve coverage.

## Limitations

- Synthetic data does not reproduce all real-world network behavior.
- No raw packet inspection is included.
- Baselines are simple statistical baselines.
- ML models are trained on generated data.
- Authentication and production-grade authorization are not implemented.
- ATT&CK mapping is intentionally evidence-driven rather than automatic.

## Future Scope

- Authorized PCAP ingestion
- Zeek/Suricata integration
- Real-time flow collection
- SIEM integration
- Threat-intelligence enrichment
- Behavioral baselines
- Better anomaly models
- Cloud IDS telemetry
- Container deployment
- Centralized logging
- Model drift monitoring

## Conclusion

The project provides a safe, modular learning environment for understanding network intrusion detection, detection engineering, security analytics, alert triage, and SOC workflows.
