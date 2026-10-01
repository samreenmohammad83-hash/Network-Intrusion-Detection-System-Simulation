"""Basic alert correlation by source, alert type, and time window."""
from datetime import datetime

def correlate_alerts(alerts: list[dict], window_seconds: int = 60) -> list[dict]:
    groups = []
    for alert in sorted(alerts, key=lambda x: x.get("timestamp","")):
        placed = False
        ts = datetime.fromisoformat(alert["timestamp"].replace("Z","+00:00"))
        for group in groups:
            head = group[0]
            hts = datetime.fromisoformat(head["timestamp"].replace("Z","+00:00"))
            if (ts-hts).total_seconds() <= window_seconds and \
               alert["source_ip"] == head["source_ip"] and \
               alert["alert_type"] == head["alert_type"]:
                group.append(alert); placed=True; break
        if not placed: groups.append([alert])
    return [{"source_ip":g[0]["source_ip"],"alert_type":g[0]["alert_type"],
             "count":len(g),"first_seen":g[0]["timestamp"],"last_seen":g[-1]["timestamp"],
             "alert_ids":[a["alert_id"] for a in g]} for g in groups]
