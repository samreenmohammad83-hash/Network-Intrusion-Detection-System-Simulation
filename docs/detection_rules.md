# Detection Rules

| ID | Rule | Default threshold | Severity |
|---|---|---:|---|
| IDS-001 | High Connection Rate | > 15 connections/sec | HIGH |
| IDS-002 | Repeated Failed Connections | failure ratio > 0.50 and >= 5 failures | HIGH |
| IDS-003 | Destination Port Diversity | >= 8 ports with >= 10 connections | MEDIUM |
| IDS-004 | SYN-Heavy Behavior | SYN ratio > 1.50 and >= 8 SYNs | HIGH |
| IDS-005 | Unusual Service-Port Activity | destination port outside common service set | MEDIUM |
| IDS-006 | High Traffic Volume | > 250,000 bytes/sec | HIGH |

Thresholds are educational defaults and should be calibrated using authorized baseline data in a production SOC.
