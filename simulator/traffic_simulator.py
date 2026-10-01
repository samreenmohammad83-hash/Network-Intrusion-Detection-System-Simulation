"""
Continuously generate synthetic flow JSON records.
Optional --api-url posts the records to a LOCAL application endpoint.
This script never creates raw network packets.
"""
import argparse, json, random, time
from datetime import datetime, timezone
from simulator.generate_dataset import base_flow

def make_flow(counter: int, mode: str):
    choices = ["NORMAL_WEB","NORMAL_DNS","NORMAL_SSH","NORMAL_EMAIL","NORMAL_DATABASE"]
    if mode == "mixed":
        choices += ["HIGH_CONNECTION_RATE","REPEATED_FAILED_CONNECTIONS",
                    "MULTI_PORT_PROBING_PATTERN","SYN_HEAVY_PATTERN",
                    "UNUSUAL_PORT_ACTIVITY","HIGH_TRAFFIC_VOLUME"]
    scenario = random.choice(choices)
    return base_flow(scenario, counter, datetime.now(timezone.utc))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["normal","mixed"], default="mixed")
    ap.add_argument("--speed", choices=["slow","fast"], default="slow")
    ap.add_argument("--api-url", default="")
    args = ap.parse_args()
    delay = 2.0 if args.speed == "slow" else 0.25
    counter = 1
    while True:
        flow = make_flow(counter, args.mode)
        payload = json.dumps(flow)
        if args.api_url:
            import requests
            try:
                r = requests.post(args.api_url.rstrip("/") + "/api/flows", json=flow, timeout=3)
                print(r.status_code, payload)
            except requests.RequestException as exc:
                print("Local API unavailable:", exc)
        else:
            print(payload)
        counter += 1
        time.sleep(delay)

if __name__ == "__main__":
    main()
