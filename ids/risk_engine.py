"""Hybrid risk scoring."""
SEVERITY_SCORE = {"INFO":10,"LOW":25,"MEDIUM":50,"HIGH":75,"CRITICAL":95}

def rule_risk(findings: list[dict]) -> float:
    if not findings: return 0.0
    return min(100.0, max(SEVERITY_SCORE.get(f["severity"],50) for f in findings) + 5*max(0,len(findings)-1))

def calculate_risk_score(rule_score: float, anomaly_score: float, ml_score: float|None=None,
                         weights: dict|None=None) -> float:
    if ml_score is None:
        weights = weights or {"rules":0.60,"anomaly":0.40}
        return round(min(100.0, rule_score*weights["rules"] + anomaly_score*weights["anomaly"]), 2)
    weights = weights or {"rules":0.40,"anomaly":0.30,"ml":0.30}
    return round(min(100.0, rule_score*weights["rules"] + anomaly_score*weights["anomaly"] + ml_score*weights["ml"]), 2)

def classify_risk(score: float) -> str:
    if score <= 20: return "NORMAL"
    if score <= 40: return "LOW RISK"
    if score <= 60: return "SUSPICIOUS"
    if score <= 80: return "HIGH RISK"
    return "CRITICAL INVESTIGATION"

def severity_from_score(score: float) -> str:
    if score <= 20: return "INFO"
    if score <= 40: return "LOW"
    if score <= 60: return "MEDIUM"
    if score <= 80: return "HIGH"
    return "CRITICAL"
