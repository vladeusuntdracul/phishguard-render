
import os, sqlite3, json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timedelta
_DB_PATH = None
def init_db(db_path: str = "data/phishguard.db"):
    global _DB_PATH
    db_path = os.getenv('PHISHGUARD_DB_PATH', db_path)
    _DB_PATH = db_path
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS detections(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            risk_level TEXT,
            confidence REAL,
            sender TEXT,
            subject TEXT,
            content_preview TEXT,
            indicators TEXT,
            urls_json TEXT
        )""")
        conn.commit()
    finally:
        conn.close()
def _connect():
    if _DB_PATH is None:
        init_db()
    return sqlite3.connect(_DB_PATH)
def save_detection(det: Dict):
    conn = _connect()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO detections(timestamp, risk_level, confidence, sender, subject, content_preview, indicators, urls_json) VALUES (?,?,?,?,?,?,?,?)",
                    (det.get("timestamp") or datetime.now().isoformat(),
                     det.get("risk_level","Unknown"),
                     float(det.get("confidence_score",0.0)),
                     det.get("sender",""),
                     det.get("subject",""),
                     det.get("content_preview",""),
                     json.dumps(det.get("indicators",[]), ensure_ascii=False),
                     json.dumps(det.get("urls",[]), ensure_ascii=False)))
        conn.commit()
    finally:
        conn.close()
def load_detections(limit: int = 200, hours_back: Optional[int] = None, risk_filter: Optional[str] = None) -> List[Dict]:
    conn = _connect()
    try:
        cur = conn.cursor()
        q = "SELECT timestamp, risk_level, confidence, sender, subject, content_preview, indicators, urls_json FROM detections"
        params, clauses = [], []
        if hours_back:
            cutoff = datetime.now() - timedelta(hours=hours_back)
            clauses.append("datetime(timestamp) >= datetime(?)"); params.append(cutoff.isoformat())
        if risk_filter:
            clauses.append("risk_level = ?"); params.append(risk_filter)
        if clauses: q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY datetime(timestamp) DESC LIMIT ?"; params.append(limit)
        rows = cur.execute(q, params).fetchall()
        return [{
            "timestamp": ts, "risk_level": rl, "confidence_score": conf, "sender": snd, "subject": sub,
            "content_preview": prev, "indicators": json.loads(inds) if inds else [], "urls": json.loads(urls) if urls else []
        } for (ts, rl, conf, snd, sub, prev, inds, urls) in rows]
    finally:
        conn.close()
def clear_all():
    conn = _connect()
    try:
        cur = conn.cursor(); cur.execute("DELETE FROM detections"); conn.commit()
    finally:
        conn.close()
