from ids.feature_extractor import extract_network_features
from ids.rule_engine import analyze_flow
from ids.anomaly_detector import build_baseline, calculate_anomaly_score
from ids.risk_engine import rule_risk, calculate_risk_score, classify_risk
from ids.alert_engine import generate_alert
from ids.correlation import correlate_alerts

class DetectionService:
    def __init__(self):
        self.baseline = None
        self.recent = []
    def set_baseline(self, rows):
        feats = [extract_network_features(r) for r in rows]
        self.baseline = build_baseline(feats)
    def analyze(self, flow):
        features = extract_network_features(flow, self.recent[-20:])
        if self.baseline is None:
            self.baseline = build_baseline([features])
        findings = analyze_flow(flow, features)
        anomaly = calculate_anomaly_score(features, self.baseline)
        rr = rule_risk(findings)
        risk = calculate_risk_score(rr, anomaly)
        classification = classify_risk(risk)
        alert = None
        if findings or anomaly >= 60:
            alert = generate_alert(flow, findings, risk, anomaly)
        self.recent.append(flow)
        self.recent = self.recent[-100:]
        return {"features":features,"findings":findings,"anomaly_score":anomaly,
                "risk_score":risk,"classification":classification,"alert":alert}

service = DetectionService()
