"""Statistical anomaly scoring using a configurable baseline."""
import math
FEATURES = ["packets_per_second","bytes_per_second","connection_rate","failure_ratio","unique_destination_ports"]

def build_baseline(feature_rows: list[dict]) -> dict:
    baseline = {}
    for name in FEATURES:
        vals = [float(r.get(name,0)) for r in feature_rows]
        if not vals:
            baseline[name] = {"mean":0.0,"std":1.0}
            continue
        mean = sum(vals)/len(vals)
        var = sum((x-mean)**2 for x in vals)/max(len(vals),1)
        baseline[name] = {"mean":mean,"std":max(math.sqrt(var), 1e-6)}
    return baseline

def calculate_anomaly_score(features: dict, baseline: dict) -> float:
    deviations = []
    for name in FEATURES:
        mean = baseline.get(name,{}).get("mean",0.0)
        std = baseline.get(name,{}).get("std",1.0)
        z = abs(float(features.get(name,0))-mean)/max(std,1e-6)
        deviations.append(min(z, 8.0))
    avg_z = sum(deviations)/len(deviations)
    return round(min(100.0, avg_z/4.0*100.0), 2)
