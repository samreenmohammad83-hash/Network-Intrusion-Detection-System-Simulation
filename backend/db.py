import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "ids.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS network_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT UNIQUE NOT NULL,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    source_port INTEGER NOT NULL,
    destination_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    packet_count REAL NOT NULL,
    byte_count REAL NOT NULL,
    duration REAL NOT NULL,
    risk_score REAL DEFAULT 0,
    classification TEXT DEFAULT 'NORMAL',
    scenario_type TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT UNIQUE NOT NULL,
    flow_id TEXT,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    description TEXT NOT NULL,
    risk_score REAL NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    anomaly_score REAL DEFAULT 0,
    ml_score REAL
);
CREATE TABLE IF NOT EXISTS rules (
    rule_id TEXT PRIMARY KEY,
    rule_name TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    threshold REAL NOT NULL,
    enabled INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS incident_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS model_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT NOT NULL,
    model_name TEXT NOT NULL,
    prediction TEXT NOT NULL,
    score REAL
);
CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON network_flows(timestamp);
CREATE INDEX IF NOT EXISTS idx_flows_source ON network_flows(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
"""

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
