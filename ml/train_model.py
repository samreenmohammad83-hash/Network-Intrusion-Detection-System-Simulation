"""Train/evaluate optional ML IDS models on generated data."""
import argparse, json
from pathlib import Path
import joblib, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
FEATURES=["packet_count","byte_count","duration_seconds","connection_count","failed_connection_count","syn_count","rst_count","average_packet_size"]

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--data",default="data/network_traffic.csv"); args=ap.parse_args()
    df=pd.read_csv(args.data); X=df[FEATURES].fillna(0); y=(df.label=="SUSPICIOUS").astype(int)
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.25,random_state=42,stratify=y)
    models={
      "logistic_regression":Pipeline([("scale",StandardScaler()),("model",LogisticRegression(max_iter=1000))]),
      "random_forest":RandomForestClassifier(n_estimators=150,random_state=42,n_jobs=-1)
    }
    results={}
    Path("models").mkdir(exist_ok=True)
    for name,m in models.items():
        m.fit(Xtr,ytr); pred=m.predict(Xte)
        results[name]={
          "accuracy":accuracy_score(yte,pred),"precision":precision_score(yte,pred,zero_division=0),
          "recall":recall_score(yte,pred,zero_division=0),"f1":f1_score(yte,pred,zero_division=0),
          "confusion_matrix":confusion_matrix(yte,pred).tolist()
        }
        joblib.dump(m,f"models/{name}.joblib")
    iso=IsolationForest(contamination=max(.05,min(.45,float(y.mean()))),random_state=42)
    iso.fit(Xtr); ipred=(iso.predict(Xte)==-1).astype(int)
    results["isolation_forest"]={"precision":precision_score(yte,ipred,zero_division=0),
      "recall":recall_score(yte,ipred,zero_division=0),"f1":f1_score(yte,ipred,zero_division=0),
      "confusion_matrix":confusion_matrix(yte,ipred).tolist()}
    with open("models/ml_metrics.json","w") as f: json.dump(results,f,indent=2)
    print(json.dumps(results,indent=2))
if __name__=="__main__": main()
