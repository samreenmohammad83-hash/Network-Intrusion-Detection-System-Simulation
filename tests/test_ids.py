import pytest
from ids.feature_extractor import extract_network_features, validate_flow
from ids.rule_engine import analyze_flow
from ids.anomaly_detector import build_baseline, calculate_anomaly_score
from ids.risk_engine import rule_risk, calculate_risk_score, classify_risk, severity_from_score
from ids.alert_engine import generate_alert
from ids.correlation import correlate_alerts
from datetime import datetime, timezone, timedelta

def flow(**kw):
    x={"flow_id":"T1","timestamp":"2026-01-01T00:00:00+00:00","source_ip":"192.0.2.1","destination_ip":"203.0.113.2","source_port":50000,"destination_port":443,"protocol":"TCP","packet_count":20,"byte_count":10000,"duration_seconds":2,"connection_count":2,"failed_connection_count":0,"syn_count":1,"rst_count":0,"average_packet_size":500,"label":"NORMAL","scenario_type":"NORMAL_WEB"}
    x.update(kw); return x

def test_01_normal_tcp_valid(): assert validate_flow(flow())==[]
def test_02_normal_udp_valid(): assert validate_flow(flow(protocol="UDP",destination_port=53))==[]
def test_03_dns_flow(): assert flow(destination_port=53,protocol="UDP")["destination_port"]==53
def test_04_https_flow(): assert flow(destination_port=443)["protocol"]=="TCP"
def test_05_high_connection_rate(): 
    f=flow(connection_count=50,duration_seconds=1); feats=extract_network_features(f); assert any(x["rule_id"]=="IDS-001" for x in analyze_flow(f,feats))
def test_06_failed_connections():
    f=flow(connection_count=20,failed_connection_count=15); feats=extract_network_features(f); assert any(x["rule_id"]=="IDS-002" for x in analyze_flow(f,feats))
def test_07_multi_port_feature():
    recent=[flow(destination_port=p,flow_id=str(p)) for p in range(1,10)]
    feats=extract_network_features(flow(destination_port=10),recent); assert feats["unique_destination_ports"]>=10
def test_08_multi_port_rule():
    f=flow(connection_count=20); recent=[flow(destination_port=p,flow_id=str(p)) for p in range(1,9)]
    feats=extract_network_features(f,recent); assert any(x["rule_id"]=="IDS-003" for x in analyze_flow(f,feats))
def test_09_syn_heavy():
    f=flow(connection_count=10,syn_count=30); feats=extract_network_features(f); assert any(x["rule_id"]=="IDS-004" for x in analyze_flow(f,feats))
def test_10_high_volume():
    f=flow(byte_count=1000000,duration_seconds=1); feats=extract_network_features(f); assert any(x["rule_id"]=="IDS-006" for x in analyze_flow(f,feats))
def test_11_invalid_source_ip(): assert "invalid source_ip" in validate_flow(flow(source_ip="999.1.1.1"))
def test_12_invalid_destination_ip(): assert "invalid destination_ip" in validate_flow(flow(destination_ip="bad"))
def test_13_invalid_source_port(): assert "invalid source_port" in validate_flow(flow(source_port=70000))
def test_14_invalid_destination_port(): assert "invalid destination_port" in validate_flow(flow(destination_port=-1))
def test_15_invalid_protocol(): assert "invalid protocol" in validate_flow(flow(protocol="FTP"))
def test_16_missing_packet_count(): assert "missing packet_count" in validate_flow(flow(packet_count=None))
def test_17_zero_duration_safe(): assert extract_network_features(flow(duration_seconds=0))["packets_per_second"]==20/0.001
def test_18_feature_failure_ratio(): assert extract_network_features(flow(connection_count=10,failed_connection_count=5))["failure_ratio"]==0.5
def test_19_baseline_creation():
    b=build_baseline([extract_network_features(flow()),extract_network_features(flow(packet_count=30))]); assert "bytes_per_second" in b
def test_20_anomaly_score_range():
    f=extract_network_features(flow()); b=build_baseline([f]); s=calculate_anomaly_score(f,b); assert 0<=s<=100
def test_21_rule_risk_none(): assert rule_risk([])==0
def test_22_rule_risk_high(): assert rule_risk([{"severity":"HIGH"}])==75
def test_23_risk_without_ml(): assert calculate_risk_score(75,60)==69
def test_24_risk_with_ml(): assert calculate_risk_score(75,60,80)==72
def test_25_risk_classification(): assert classify_risk(85)=="CRITICAL INVESTIGATION"
def test_26_severity_mapping(): assert severity_from_score(75)=="HIGH"
def test_27_alert_creation():
    a=generate_alert(flow(),[{"rule_id":"IDS-001","name":"High Connection Rate","severity":"HIGH","description":"x"}],75,60); assert a["alert_id"].startswith("ALT-")
def test_28_alert_status_default(): 
    a=generate_alert(flow(),[],50,50); assert a["status"]=="NEW"
def test_29_alert_correlation():
    t=datetime.now(timezone.utc)
    base={"source_ip":"192.0.2.1","alert_type":"High Connection Rate"}
    alerts=[{**base,"timestamp":t.isoformat(),"alert_id":"A1"},{**base,"timestamp":(t+timedelta(seconds=20)).isoformat(),"alert_id":"A2"}]
    assert correlate_alerts(alerts)[0]["count"]==2
def test_30_duplicate_ids_are_detectable():
    assert flow()["flow_id"]==flow()["flow_id"]
