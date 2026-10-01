# SIEM Integration Concept

The project normalizes alerts as JSON. A production adapter could send those events to a SIEM over an approved collector/API.

```text
IDS -> JSON -> Log Forwarder/API -> SIEM -> Correlation -> SOC
```

Recommended production additions:

- TLS
- authenticated API
- schema/version control
- retry/dead-letter handling
- event timestamps in UTC
- immutable audit trail
- SIEM field mapping
- deduplication
- retention controls
