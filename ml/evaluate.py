import argparse, json, subprocess, sys
ap=argparse.ArgumentParser(); ap.add_argument("--data",default="data/network_traffic.csv"); args=ap.parse_args()
subprocess.run([sys.executable,"ml/train_model.py","--data",args.data],check=True)
with open("models/ml_metrics.json") as f: print(json.dumps(json.load(f),indent=2))
