# Interview Preparation — 10 Questions and Answers

## 1. Explain your project.
I built a defensive Network Intrusion Detection System simulation that works with synthetic network-flow records. I implemented feature extraction, configurable signature rules, statistical anomaly detection, optional machine learning, hybrid risk scoring, alert generation, correlation, SQLite storage, a FastAPI backend, and a React SOC dashboard. The project is safe because it does not generate attack packets or scan external systems.

## 2. What is an IDS?
An IDS is a security monitoring system that detects activity matching known rules or unusual behavior and generates alerts for investigation. My project simulates a network-based IDS using flow metadata.

## 3. What is the difference between signature and anomaly detection?
Signature detection checks for predefined patterns, so the reason for an alert is usually easy to explain. Anomaly detection compares activity with a baseline and can identify unusual behavior that was not explicitly written as a rule, but it can produce more false positives.

## 4. Which features did you engineer?
I used packet count, byte count, duration, bytes per second, packets per second, connection count, failed connection count, failure ratio, SYN count, RST count, SYN ratio, destination-port diversity, destination-IP diversity, and connection rate.

## 5. How does your risk score work?
I convert rule findings and anomaly deviation into 0–100 scores. With ML enabled, the default weights are 40% rules, 30% anomaly and 30% ML. Without ML, rules are 60% and anomaly is 40%. These are project assumptions that would need calibration using real SOC data.

## 6. How do you generate alerts?
If one or more detection rules match, or the anomaly score crosses the configured alert threshold, the alert engine creates a normalized alert with source/destination, rule, severity, risk score, description and status.

## 7. What machine-learning models did you use?
I included Logistic Regression and Random Forest as supervised classifiers and Isolation Forest as an unsupervised detector. The training script calculates accuracy, precision, recall, F1 and a confusion matrix rather than inventing results.

## 8. What are false positives and false negatives?
A false positive is legitimate activity flagged as suspicious. A false negative is suspicious activity that the detector misses. In a SOC, both matter because analysts need useful alerts while important activity should not be overlooked.

## 9. How would a SOC analyst use this project?
A Tier-1 analyst can triage the alert, review network context, compare the flow with baseline behavior, check related alerts, determine whether the activity is expected, document notes and update the incident status.

## 10. Why did you build an IDS instead of an IPS?
The project is intentionally an IDS because the educational goal is detection and investigation. An IPS can take preventive action, which is not necessary for this simulation and could create unnecessary operational risk.
