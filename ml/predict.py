import argparse, joblib, pandas as pd
FEATURES=["packet_count","byte_count","duration_seconds","connection_count","failed_connection_count","syn_count","rst_count","average_packet_size"]
def predict(model_path, flow):
    model=joblib.load(model_path)
    X=pd.DataFrame([flow])[FEATURES].fillna(0)
    pred=int(model.predict(X)[0])
    prob=float(model.predict_proba(X)[0,1]) if hasattr(model,"predict_proba") else float(pred)
    return {"prediction":"SUSPICIOUS" if pred else "NORMAL","score":round(prob*100,2)}
if __name__=="__main__":
    ap=argparse.ArgumentParser(); ap.add_argument("--model",default="models/random_forest.joblib"); ap.add_argument("--data",default="data/network_traffic.csv"); args=ap.parse_args()
    df=pd.read_csv(args.data); print(predict(args.model,df.iloc[0].to_dict()))
