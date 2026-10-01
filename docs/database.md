# Database Design

`network_flows` stores flow metadata and final risk/classification.

`alerts` stores normalized detection events and their investigation status.

`rules` stores configurable rule definitions and thresholds.

`incident_notes` stores analyst notes associated with alerts.

`model_results` is available for optional ML predictions.

Indexes support timestamp, source IP, alert status and severity filtering.
