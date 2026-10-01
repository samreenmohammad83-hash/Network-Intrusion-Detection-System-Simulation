"""Validation and feature engineering for synthetic network flows."""
from ipaddress import ip_address
from math import isfinite

VALID_PROTOCOLS = {"TCP","UDP","ICMP"}

def _num(value, default=0.0):
    try:
        x = float(value)
        return x if isfinite(x) else default
    except (TypeError, ValueError):
        return default

def validate_flow(flow: dict) -> list[str]:
    errors = []
    for key in ("source_ip","destination_ip"):
        try:
            ip_address(str(flow.get(key)))
        except ValueError:
            errors.append(f"invalid {key}")
    for key in ("source_port","destination_port"):
        try:
            p = int(flow.get(key))
            if not 0 <= p <= 65535: raise ValueError
        except (TypeError, ValueError):
            errors.append(f"invalid {key}")
    if str(flow.get("protocol","")).upper() not in VALID_PROTOCOLS:
        errors.append("invalid protocol")
    if flow.get("packet_count") is None:
        errors.append("missing packet_count")
    return errors

def extract_network_features(flow: dict, recent_flows: list[dict] | None = None) -> dict:
    recent_flows = recent_flows or []
    duration = _num(flow.get("duration_seconds"))
    packets = _num(flow.get("packet_count"))
    bytes_ = _num(flow.get("byte_count"))
    connections = _num(flow.get("connection_count"))
    failed = _num(flow.get("failed_connection_count"))
    syn = _num(flow.get("syn_count"))
    rst = _num(flow.get("rst_count"))
    avg_size = _num(flow.get("average_packet_size"))
    ports = {int(flow.get("destination_port", 0))}
    ips = {str(flow.get("destination_ip", ""))}
    for f in recent_flows:
        try:
            ports.add(int(f.get("destination_port")))
            ips.add(str(f.get("destination_ip")))
        except (TypeError, ValueError):
            pass
    safe_duration = max(duration, 0.001)
    return {
        "packet_count": packets,
        "byte_count": bytes_,
        "duration": duration,
        "bytes_per_second": bytes_ / safe_duration,
        "packets_per_second": packets / safe_duration,
        "average_packet_size": avg_size or bytes_ / max(packets, 1),
        "connection_count": connections,
        "failed_connection_count": failed,
        "failure_ratio": failed / max(connections, 1),
        "syn_count": syn,
        "rst_count": rst,
        "syn_ratio": syn / max(connections, 1),
        "unique_destination_ports": len(ports),
        "unique_destination_ips": len(ips),
        "connection_rate": connections / safe_duration,
    }
