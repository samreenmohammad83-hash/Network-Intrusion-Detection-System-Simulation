import React,{useEffect,useState} from "react";
import {LineChart,Line,XAxis,YAxis,Tooltip,CartesianGrid,BarChart,Bar,PieChart,Pie,Cell,ResponsiveContainer} from "recharts";
const API="http://127.0.0.1:8000";
export default function App(){
 const [stats,setStats]=useState({}),[alerts,setAlerts]=useState([]),[traffic,setTraffic]=useState([]),[charts,setCharts]=useState({});
 const [selected,setSelected]=useState(null),[note,setNote]=useState("");
 const load=async()=>{const [s,a,t,c]=await Promise.all([
   fetch(API+"/api/dashboard/stats").then(r=>r.json()),fetch(API+"/api/alerts?limit=30").then(r=>r.json()),
   fetch(API+"/api/dashboard/traffic").then(r=>r.json()),fetch(API+"/api/dashboard/alerts").then(r=>r.json())]);
   setStats(s);setAlerts(a);setTraffic(t);setCharts(c)};
 useEffect(()=>{load();const id=setInterval(load,3000);return()=>clearInterval(id)},[]);
 const open=async(id)=>setSelected(await fetch(API+"/api/alerts/"+id).then(r=>r.json()));
 const status=async(s)=>{await fetch(API+"/api/alerts/"+selected.alert.alert_id+"/status",{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify({status:s})});load();open(selected.alert.alert_id)};
 const addNote=async()=>{if(!note.trim())return;await fetch(API+"/api/alerts/"+selected.alert.alert_id+"/notes",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({note})});setNote("");open(selected.alert.alert_id)};
 return <div className="app"><header><div><h1>Network IDS SOC</h1><p>Defensive synthetic-flow monitoring</p></div><span className="live">● LIVE SIMULATION</span></header>
 <section className="cards">{[
 ["Total Flows",stats.total_flows],["Normal",stats.normal_traffic],["Suspicious",stats.suspicious_traffic],
 ["Open Alerts",stats.open_alerts],["Critical",stats.critical_alerts],["Avg Risk",stats.average_risk_score]
 ].map(([k,v])=><div className="card" key={k}><small>{k}</small><strong>{v??0}</strong></div>)}</section>
 <section className="grid"><div className="panel wide"><h2>Traffic & Risk Timeline</h2><ResponsiveContainer width="100%" height={280}><LineChart data={traffic}><CartesianGrid strokeDasharray="3 3"/><XAxis dataKey="bucket"/><YAxis/><Tooltip/><Line type="monotone" dataKey="flows"/><Line type="monotone" dataKey="avg_risk"/></LineChart></ResponsiveContainer></div>
 <div className="panel"><h2>Severity</h2><ResponsiveContainer width="100%" height={280}><BarChart data={charts.severity||[]}><XAxis dataKey="severity"/><YAxis/><Tooltip/><Bar dataKey="count"/></BarChart></ResponsiveContainer></div>
 <div className="panel"><h2>Protocols</h2><ResponsiveContainer width="100%" height={280}><PieChart><Pie data={charts.protocols||[]} dataKey="count" nameKey="protocol" outerRadius={90} label>{(charts.protocols||[]).map((x,i)=><Cell key={i}/>)}</Pie><Tooltip/></PieChart></ResponsiveContainer></div>
 <div className="panel"><h2>Top Alert Types</h2><ResponsiveContainer width="100%" height={280}><BarChart data={charts.types||[]} layout="vertical"><XAxis type="number"/><YAxis type="category" dataKey="alert_type" width={150}/><Tooltip/><Bar dataKey="count"/></BarChart></ResponsiveContainer></div></section>
 <section className="panel"><div className="row"><h2>Recent Alerts</h2><button onClick={load}>Refresh</button></div><div className="tableWrap"><table><thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Alert</th><th>Severity</th><th>Risk</th><th>Status</th></tr></thead>
 <tbody>{alerts.map(a=><tr key={a.alert_id} onClick={()=>open(a.alert_id)}><td>{a.created_at?.slice(11,19)}</td><td>{a.source_ip}</td><td>{a.destination_ip}:{a.destination_port}</td><td>{a.protocol}</td><td>{a.alert_type}</td><td><span className={"sev "+a.severity.toLowerCase()}>{a.severity}</span></td><td>{a.risk_score}</td><td>{a.status}</td></tr>)}</tbody></table></div></section>
 {selected&&<div className="modal"><div className="modalbox"><div className="row"><h2>{selected.alert.alert_id}</h2><button onClick={()=>setSelected(null)}>Close</button></div>
 <p><b>Type:</b> {selected.alert.alert_type} &nbsp; <b>Severity:</b> {selected.alert.severity} &nbsp; <b>Risk:</b> {selected.alert.risk_score}/100</p>
 <p><b>Source:</b> {selected.alert.source_ip}:{selected.alert.source_port} → <b>Destination:</b> {selected.alert.destination_ip}:{selected.alert.destination_port}</p>
 <p><b>Rule:</b> {selected.alert.rule_id} — {selected.alert.description}</p><p><b>Anomaly:</b> {selected.alert.anomaly_score} &nbsp; <b>ML:</b> {selected.alert.ml_score??"disabled"}</p>
 <div className="actions">{["NEW","INVESTIGATING","RESOLVED","FALSE_POSITIVE"].map(s=><button onClick={()=>status(s)} key={s}>{s}</button>)}</div>
 <textarea value={note} onChange={e=>setNote(e.target.value)} placeholder="Analyst note"/><button onClick={addNote}>Add Note</button>
 <h3>Incident Notes</h3>{selected.notes.map(n=><div className="note" key={n.id}><small>{n.created_at}</small><br/>{n.note}</div>)}</div></div>}</div>
}
