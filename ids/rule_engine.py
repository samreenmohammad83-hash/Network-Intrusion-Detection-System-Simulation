"""Configurable signature/rule detection for synthetic flows."""
DEFAULT_RULES = {
    "IDS-001": {"name":"High Connection Rate","severity":"HIGH","threshold":15.0,"field":"connection_rate","description":"Connection rate exceeded configured baseline."},
    "IDS-002": {"name":"Repeated Failed Connections","severity":"HIGH","threshold":0.50,"field":"failure_ratio","description":"Failure ratio exceeded configured baseline."},
    "IDS-003": {"name":"Destination Port Diversity","severity":"MEDIUM","threshold":8.0,"field":"unique_destination_ports","description":"Destination-port diversity exceeded configured baseline."},
    "IDS-004": {"name":"SYN-Heavy Behavior","severity":"HIGH","threshold":1.50,"field":"syn_ratio","description":"SYN activity exceeded configured baseline."},
    "IDS-005": {"name":"Unusual Service-Port Activity","severity":"MEDIUM","threshold":0.0,"field":"unusual_port","description":"Destination port is outside the configured common service-port set."},
    "IDS-006": {"name":"High Traffic Volume","severity":"HIGH","threshold":250000.0,"field":"bytes_per_second","description":"Byte rate exceeded configured traffic baseline."},
}
KNOWN_SERVICE_PORTS = {22,25,53,80,110,143,443,465,587,993,995,1433,3306,5432,6379,8080}

def analyze_flow(flow: dict, features: dict, rules=None) -> list[dict]:
    rules = rules or DEFAULT_RULES
    findings = []
    if features["connection_rate"] > rules["IDS-001"]["threshold"]:
        findings.append({**rules["IDS-001"],"rule_id":"IDS-001","description":"Connection rate exceeded configured baseline."})
    if features["failure_ratio"] > rules["IDS-002"]["threshold"] and features["failed_connection_count"] >= 5:
        findings.append({**rules["IDS-002"],"rule_id":"IDS-002","description":"Failure ratio and failed connection count exceeded thresholds."})
    if features["unique_destination_ports"] >= rules["IDS-003"]["threshold"] and features["connection_count"] >= 10:
        findings.append({**rules["IDS-003"],"rule_id":"IDS-003","description":"Destination-port diversity exceeded the configured threshold."})
    if features["syn_ratio"] > rules["IDS-004"]["threshold"] and features["syn_count"] >= 8:
        findings.append({**rules["IDS-004"],"rule_id":"IDS-004","description":"SYN activity was unusually high relative to connections."})
    dport = int(flow.get("destination_port", 0))
    if dport not in KNOWN_SERVICE_PORTS and dport != 0:
        findings.append({**rules["IDS-005"],"rule_id":"IDS-005","description":"Destination port is outside the configured common service-port set."})
    if features["bytes_per_second"] > rules["IDS-006"]["threshold"]:
        findings.append({**rules["IDS-006"],"rule_id":"IDS-006","description":"Byte rate exceeded configured traffic baseline."})
    return findings
