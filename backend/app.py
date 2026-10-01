from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone
from backend.db import init_db, get_conn
from backend.schemas import FlowIn, StatusUpdate, NoteIn
from backend.services.detection_service import service
from ids.rule_engine import DEFAULT_RULES
import csv, os

app = FastAPI(title="Network IDS Simulation API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS","http://localhost:5173").split(","),
    allow_credentials=False, allow_methods=["*"], allow_headers=["*"]
)

@app.on_event("startup")
def startup():
    init_db()
    conn=get_conn()
    for rid,r in DEFAULT_RULES.items():
        conn.execute("""INSERT OR IGNORE INTO rules(rule_id,rule_name,description,severity,threshold,enabled)
                        VALUES(?,?,?,?,?,1)""",
                     (rid,r["name"],r["description"],r["severity"],r["threshold"]))
    conn.commit(); conn.close()
    path="data/network_traffic.csv"
    if os.path.exists(path):
        with open(path,encoding="utf-8") as f:
            rows=list(csv.DictReader(f))[:1000]
        service.set_baseline(rows)

@app.get("/health")
def health(): return {"status":"ok","service":"network-ids-simulation"}

@app.post("/api/flows")
def ingest_flow(flow: FlowIn):
    data=flow.model_dump()
    result=service.analyze(data)
    conn=get_conn()
    try:
        conn.execute("""INSERT INTO network_flows
        (flow_id,timestamp,source_ip,destination_ip,source_port,destination_port,protocol,
         packet_count,byte_count,duration,risk_score,classification,scenario_type)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (data["flow_id"],data["timestamp"],data["source_ip"],data["destination_ip"],
         data["source_port"],data["destination_port"],data["protocol"],data["packet_count"],
         data["byte_count"],data["duration_seconds"],result["risk_score"],result["classification"],data["scenario_type"]))
    except Exception as exc:
        conn.close(); raise HTTPException(409,f"duplicate or invalid flow: {exc}")
    if result["alert"]:
        a=result["alert"]
        conn.execute("""INSERT INTO alerts
        (alert_id,flow_id,rule_id,severity,alert_type,description,risk_score,status,created_at,
         source_ip,destination_ip,protocol,source_port,destination_port,anomaly_score,ml_score)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (a["alert_id"],data["flow_id"],a["rule_id"],a["severity"],a["alert_type"],a["description"],
         a["risk_score"],a["status"],a["timestamp"],a["source_ip"],a["destination_ip"],a["protocol"],
         a["source_port"],a["destination_port"],a["anomaly_score"],a["ml_score"]))
    conn.commit(); conn.close()
    return {"flow":data,"detection":result}

@app.get("/api/flows")
def list_flows(limit:int=Query(100,ge=1,le=1000)):
    conn=get_conn(); rows=[dict(r) for r in conn.execute("SELECT * FROM network_flows ORDER BY id DESC LIMIT ?",(limit,)).fetchall()]; conn.close()
    return rows

@app.get("/api/flows/{flow_id}")
def get_flow(flow_id:str):
    conn=get_conn(); row=conn.execute("SELECT * FROM network_flows WHERE flow_id=?",(flow_id,)).fetchone(); conn.close()
    if not row: raise HTTPException(404,"flow not found")
    return dict(row)

@app.get("/api/alerts")
def list_alerts(status:str|None=None, severity:str|None=None, limit:int=Query(100,ge=1,le=500)):
    conn=get_conn()
    q="SELECT * FROM alerts WHERE 1=1"; params=[]
    if status: q+=" AND status=?"; params.append(status)
    if severity: q+=" AND severity=?"; params.append(severity)
    q+=" ORDER BY id DESC LIMIT ?"; params.append(limit)
    rows=[dict(r) for r in conn.execute(q,params).fetchall()]; conn.close(); return rows

@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id:str):
    conn=get_conn()
    row=conn.execute("SELECT * FROM alerts WHERE alert_id=?",(alert_id,)).fetchone()
    notes=[dict(r) for r in conn.execute("SELECT * FROM incident_notes WHERE alert_id=? ORDER BY id DESC",(alert_id,)).fetchall()]
    conn.close()
    if not row: raise HTTPException(404,"alert not found")
    return {"alert":dict(row),"notes":notes}

@app.put("/api/alerts/{alert_id}/status")
def update_status(alert_id:str, body:StatusUpdate):
    conn=get_conn(); cur=conn.execute("UPDATE alerts SET status=? WHERE alert_id=?",(body.status,alert_id)); conn.commit(); conn.close()
    if cur.rowcount==0: raise HTTPException(404,"alert not found")
    return {"alert_id":alert_id,"status":body.status}

@app.post("/api/alerts/{alert_id}/notes")
def add_note(alert_id:str, body:NoteIn):
    conn=get_conn()
    if not conn.execute("SELECT 1 FROM alerts WHERE alert_id=?",(alert_id,)).fetchone():
        conn.close(); raise HTTPException(404,"alert not found")
    now=datetime.now(timezone.utc).isoformat()
    conn.execute("INSERT INTO incident_notes(alert_id,note,created_at) VALUES(?,?,?)",(alert_id,body.note,now))
    conn.commit(); conn.close()
    return {"alert_id":alert_id,"note":body.note,"created_at":now}

@app.get("/api/dashboard/stats")
def dashboard_stats():
    conn=get_conn()
    total=conn.execute("SELECT COUNT(*) c FROM network_flows").fetchone()["c"]
    normal=conn.execute("SELECT COUNT(*) c FROM network_flows WHERE classification='NORMAL'").fetchone()["c"]
    suspicious=total-normal
    open_alerts=conn.execute("SELECT COUNT(*) c FROM alerts WHERE status IN ('NEW','INVESTIGATING')").fetchone()["c"]
    critical=conn.execute("SELECT COUNT(*) c FROM alerts WHERE severity='CRITICAL' AND status!='RESOLVED'").fetchone()["c"]
    avg=conn.execute("SELECT COALESCE(AVG(risk_score),0) a FROM network_flows").fetchone()["a"]
    conn.close()
    return {"total_flows":total,"normal_traffic":normal,"suspicious_traffic":suspicious,
            "open_alerts":open_alerts,"critical_alerts":critical,"average_risk_score":round(avg,2)}

@app.get("/api/dashboard/traffic")
def dashboard_traffic():
    conn=get_conn()
    rows=[dict(r) for r in conn.execute("""SELECT substr(timestamp,1,16) bucket,
        COUNT(*) flows, ROUND(AVG(risk_score),2) avg_risk
        FROM network_flows GROUP BY bucket ORDER BY bucket DESC LIMIT 60""").fetchall()]
    conn.close(); return list(reversed(rows))

@app.get("/api/dashboard/alerts")
def dashboard_alerts():
    conn=get_conn()
    sev=[dict(r) for r in conn.execute("SELECT severity,COUNT(*) count FROM alerts GROUP BY severity").fetchall()]
    types=[dict(r) for r in conn.execute("SELECT alert_type,COUNT(*) count FROM alerts GROUP BY alert_type ORDER BY count DESC LIMIT 10").fetchall()]
    proto=[dict(r) for r in conn.execute("SELECT protocol,COUNT(*) count FROM network_flows GROUP BY protocol").fetchall()]
    ports=[dict(r) for r in conn.execute("SELECT destination_port,COUNT(*) count FROM network_flows GROUP BY destination_port ORDER BY count DESC LIMIT 10").fetchall()]
    sources=[dict(r) for r in conn.execute("SELECT source_ip,COUNT(*) count FROM alerts GROUP BY source_ip ORDER BY count DESC LIMIT 10").fetchall()]
    conn.close()
    return {"severity":sev,"types":types,"protocols":proto,"ports":ports,"sources":sources}

@app.get("/api/rules")
def get_rules():
    conn=get_conn(); rows=[dict(r) for r in conn.execute("SELECT * FROM rules ORDER BY rule_id").fetchall()]; conn.close(); return rows

@app.put("/api/rules/{rule_id}")
def update_rule(rule_id:str, threshold:float=Query(...), enabled:bool=True):
    conn=get_conn(); cur=conn.execute("UPDATE rules SET threshold=?,enabled=? WHERE rule_id=?",(threshold,int(enabled),rule_id)); conn.commit(); conn.close()
    if cur.rowcount==0: raise HTTPException(404,"rule not found")
    return {"rule_id":rule_id,"threshold":threshold,"enabled":enabled}
