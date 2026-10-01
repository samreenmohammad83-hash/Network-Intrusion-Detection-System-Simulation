"""
Generate safe synthetic network-flow records.
No packets are generated or transmitted.
"""
import argparse
import csv
import random
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address

SCENARIOS = [
    "NORMAL_WEB", "NORMAL_DNS", "NORMAL_SSH", "NORMAL_EMAIL", "NORMAL_DATABASE",
    "HIGH_CONNECTION_RATE", "REPEATED_FAILED_CONNECTIONS",
    "MULTI_PORT_PROBING_PATTERN", "SYN_HEAVY_PATTERN",
    "UNUSUAL_PORT_ACTIVITY", "HIGH_TRAFFIC_VOLUME"
]
FIELDS = [
    "flow_id","timestamp","source_ip","destination_ip","source_port",
    "destination_port","protocol","packet_count","byte_count","duration_seconds",
    "connection_count","failed_connection_count","syn_count","rst_count",
    "average_packet_size","label","scenario_type"
]
NORMAL = SCENARIOS[:5]
SUSPICIOUS = SCENARIOS[5:]

def ip_in_octet(base: str) -> str:
    return f"{base}.{random.randint(1, 254)}"

def base_flow(scenario: str, i: int, now: datetime) -> dict:
    normal = scenario in NORMAL
    protocol = random.choice(["TCP", "UDP"])
    src = ip_in_octet(random.choice(["192.0.2", "198.51.100"]))
    dst = ip_in_octet("203.0.113")
    ports = {
        "NORMAL_WEB": (443, "TCP"), "NORMAL_DNS": (53, "UDP"),
        "NORMAL_SSH": (22, "TCP"), "NORMAL_EMAIL": (587, "TCP"),
        "NORMAL_DATABASE": (5432, "TCP")
    }
    if scenario in ports:
        dport, protocol = ports[scenario]
    elif scenario == "HIGH_CONNECTION_RATE":
        dport, protocol = random.choice([80,443,22]), "TCP"
    elif scenario == "REPEATED_FAILED_CONNECTIONS":
        dport, protocol = random.choice([22,3389,443]), "TCP"
    elif scenario == "MULTI_PORT_PROBING_PATTERN":
        dport, protocol = random.randint(1, 65535), "TCP"
    elif scenario == "SYN_HEAVY_PATTERN":
        dport, protocol = random.choice([80,443]), "TCP"
    elif scenario == "UNUSUAL_PORT_ACTIVITY":
        dport, protocol = random.choice([4444,31337,8088,9001]), "TCP"
    else:
        dport, protocol = random.choice([80,443,8080]), "TCP"

    packet_count = random.randint(5, 80)
    duration = round(random.uniform(0.2, 10.0), 2)
    connection_count = random.randint(1, 5)
    failed = random.randint(0, 1)
    syn = random.randint(0, min(connection_count + 2, 5))
    rst = random.randint(0, 1)

    if scenario == "HIGH_CONNECTION_RATE":
        connection_count = random.randint(35, 100)
        duration = round(random.uniform(0.5, 2.0), 2)
    elif scenario == "REPEATED_FAILED_CONNECTIONS":
        connection_count = random.randint(10, 30)
        failed = random.randint(7, connection_count)
        rst = random.randint(2, 8)
    elif scenario == "MULTI_PORT_PROBING_PATTERN":
        connection_count = random.randint(20, 70)
        packet_count = random.randint(20, 100)
        syn = random.randint(10, 60)
    elif scenario == "SYN_HEAVY_PATTERN":
        connection_count = random.randint(15, 50)
        syn = random.randint(int(connection_count*0.8), connection_count*2)
        rst = random.randint(5, 20)
    elif scenario == "UNUSUAL_PORT_ACTIVITY":
        connection_count = random.randint(5, 25)
        failed = random.randint(0, 4)
    elif scenario == "HIGH_TRAFFIC_VOLUME":
        packet_count = random.randint(2000, 10000)
        duration = round(random.uniform(1, 20), 2)

    avg_size = random.randint(250, 1400)
    byte_count = packet_count * avg_size
    return {
        "flow_id": f"FLOW-{i:06d}",
        "timestamp": (now - timedelta(seconds=random.randint(0, 86400))).isoformat(),
        "source_ip": src,
        "destination_ip": dst,
        "source_port": random.randint(1024, 65535),
        "destination_port": dport,
        "protocol": protocol,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": duration,
        "connection_count": connection_count,
        "failed_connection_count": failed,
        "syn_count": syn,
        "rst_count": rst,
        "average_packet_size": round(byte_count / max(packet_count, 1), 2),
        "label": "NORMAL" if normal else "SUSPICIOUS",
        "scenario_type": scenario
    }

def generate(records: int, seed: int = 42) -> list[dict]:
    random.seed(seed)
    now = datetime.now(timezone.utc)
    rows = []
    for i in range(1, records + 1):
        scenario = random.choice(NORMAL if i <= records * 0.65 else SUSPICIOUS)
        rows.append(base_flow(scenario, i, now))
    random.shuffle(rows)
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", type=int, default=5000)
    ap.add_argument("--output", default="data/network_traffic.csv")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    rows = generate(args.records, args.seed)
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"Generated {len(rows)} synthetic flows -> {args.output}")

if __name__ == "__main__":
    main()
