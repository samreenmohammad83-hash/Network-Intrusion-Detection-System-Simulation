"""Alert creation."""
from datetime import datetime, timezone
import uuid
from ids.risk_engine import severity_from_score

def generate_alert(flow: dict, findings: list[dict], risk_score: float, anomaly_score: float, ml_score=None) -> dict:
    primary = findings[0] if findings else {
        "rule_id":"ANOMALY-001","name":"Statistical Anomaly",
        "description":"Flow deviated from the configured baseline.",
        "severity":severity_from_score(risk_score)
    }
    return {
        "alert_id": "ALT-" + uuid.uuid4().hex[:8].upper(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": flow["source_ip"], "destination_ip": flow["destination_ip"],
        "protocol": flow["protocol"], "source_port": flow["source_port"],
        "destination_port": flow["destination_port"], "rule_id": primary["rule_id"],
        "alert_type": primary["name"], "severity": severity_from_score(risk_score),
        "risk_score": round(risk_score,2),
        "anomaly_score": round(anomaly_score,2),
        "ml_score": None if ml_score is None else round(ml_score,2),
        "description": primary["description"], "status":"NEW"
    }
