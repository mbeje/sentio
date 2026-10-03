"""
SecureFileVault — Complex Demo Target for SENTIO Phase 2
A realistic file-storage API with auth, RBAC, SQLite, simulated processing,
timing side-channels, and multiple endpoint complexity profiles.
Run: python target/target_app.py
"""
import os
import sys
import sqlite3
import hashlib
import hmac
import secrets
import time
import random
import string
import threading
import json
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, g, send_file
import jwt

# ── Configuration ──
app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(32)
app.config["DATABASE"] = os.path.join(os.path.dirname(__file__), "vault.db")
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB
app.config["SENTIO_MONITOR_ENDPOINT"] = os.getenv("SENTIO_MONITOR_URL", "")

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# ── Database ──
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(app.config["DATABASE"])
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user' CHECK(role IN ('user','admin','service')),
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            api_quota INTEGER DEFAULT 1000
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            file_size INTEGER,
            content_type TEXT,
            checksum TEXT,
            encrypted INTEGER DEFAULT 0,
            upload_time TEXT DEFAULT CURRENT_TIMESTAMP,
            scan_status TEXT DEFAULT 'pending' CHECK(scan_status IN ('pending','clean','infected','error')),
            scan_duration_ms INTEGER
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            action TEXT NOT NULL,
            resource TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            success INTEGER DEFAULT 1,
            duration_ms REAL,
            details TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            token_jti TEXT UNIQUE NOT NULL,
            issued_at TEXT,
            expires_at TEXT,
            revoked INTEGER DEFAULT 0
        );
    """)
    # Seed admin if not exists
    admin_hash = hashlib.pbkdf2_hmac("sha256", b"admin123", b"sentio-salt", 100000).hex()
    db.execute("""
        INSERT OR IGNORE INTO users (id, username, password_hash, role, api_quota)
        VALUES (1, 'admin', ?, 'admin', 99999)
    """, (admin_hash,))
    db.commit()
    db.close()

# ── Metrics Middleware ──
@app.before_request
def before_request():
    g.start_time = time.time()
    g.request_id = secrets.token_hex(6)
    g.db = get_db()

@app.after_request
def after_request(response):
    duration = (time.time() - g.start_time) * 1000
    db = g.get("db")
    if db:
        try:
            db.execute("""
                INSERT INTO audit_logs (action, resource, ip_address, user_agent, duration_ms, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                request.method,
                request.path,
                request.remote_addr,
                request.user_agent.string[:100] if request.user_agent else "",
                round(duration, 2),
                json.dumps({"status_code": response.status_code, "request_id": g.request_id})
            ))
            db.commit()
        except Exception:
            pass

    # Push to SENTIO monitor if configured
    if app.config["SENTIO_MONITOR_ENDPOINT"]:
        try:
            import requests
            requests.post(app.config["SENTIO_MONITOR_ENDPOINT"], json={
                "timestamp": datetime.utcnow().isoformat(),
                "endpoint": request.path,
                "method": request.method,
                "status_code": response.status_code,
                "duration_ms": round(duration, 2),
                "request_size": request.content_length or 0,
                "response_size": response.content_length or 0,
            }, timeout=0.5)
        except Exception:
            pass

    return response

# ── Auth Helpers ──
def hash_password(pw: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), b"sentio-salt", 100000).hex()

def generate_tokens(user_id: int, role: str):
    now = datetime.utcnow()
    access_payload = {
        "sub": user_id, "role": role, "type": "access",
        "iat": now, "exp": now + timedelta(minutes=15),
        "jti": secrets.token_hex(8)
    }
    refresh_payload = {
        "sub": user_id, "role": role, "type": "refresh",
        "iat": now, "exp": now + timedelta(days=7),
        "jti": secrets.token_hex(8)
    }
    return (
        jwt.encode(access_payload, app.config["SECRET_KEY"], algorithm="HS256"),
        jwt.encode(refresh_payload, app.config["SECRET_KEY"], algorithm="HS256"),
    )

def token_required(roles=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify({"error": "Missing token"}), 401
            try:
                token = auth.split(" ")[1]
                payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
                if payload.get("type") != "access":
                    return jsonify({"error": "Invalid token type"}), 401
                if roles and payload.get("role") not in roles:
                    return jsonify({"error": "Insufficient privileges"}), 403
                g.current_user = payload
                return f(*args, **kwargs)
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Invalid token"}), 401
        return wrapper
    return decorator

# ── Simulated Processing ──
def simulate_av_scan(file_path: str) -> tuple:
    """Simulates antivirus scanning with variable CPU load and timing."""
    start = time.time()
    file_size = os.path.getsize(file_path)

    # Simulate reading and hashing the file (CPU work)
    with open(file_path, "rb") as f:
        while f.read(8192):
            pass

    # Simulate heuristic analysis — duration scales with file size
    base_delay = 0.05 + (file_size / (1024 * 1024)) * 0.02  # ~20ms per MB
    noise = random.uniform(-0.01, 0.05)
    time.sleep(max(0.01, base_delay + noise))

    duration = int((time.time() - start) * 1000)
    # 2% chance of simulated infection detection
    status = "infected" if random.random() < 0.02 else "clean"
    return status, duration

def simulate_db_backup():
    """Simulates heavy admin backup operation."""
    time.sleep(random.uniform(0.5, 2.0))
    return {"tables_backed_up": 5, "rows": random.randint(10000, 50000)}

# ═══════════════════════════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@app.route("/api/health", methods=["GET"])
def health():
    """Fast health check. Returns system-like metrics."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.4.1",
        "uptime_seconds": int(time.time() % 86400),
        "db_connections": random.randint(3, 12),
        "memory_usage_mb": round(random.uniform(120, 340), 1),
        "cpu_load": round(random.uniform(0.1, 0.4), 2),
    })

@app.route("/api/auth/register", methods=["POST"])
def register():
    """User registration. Light, fast endpoint."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    if not username or not password or len(password) < 6:
        return jsonify({"error": "Invalid credentials"}), 400

    pw_hash = hash_password(password)
    try:
        g.db.execute("""
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, 'user')
        """, (username, pw_hash))
        g.db.commit()
        return jsonify({"message": "User created", "username": username}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username exists"}), 409

@app.route("/api/auth/login", methods=["POST"])
def login():
    """Authentication with intentional timing side-channel for failed attempts."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")

    user = g.db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not user:
        # Intentional timing leak: hash anyway to keep timing similar
        hash_password(password)
        time.sleep(random.uniform(0.05, 0.12))
        return jsonify({"error": "Invalid credentials"}), 401

    # Check lockout
    locked_until = user["locked_until"]
    if locked_until and datetime.fromisoformat(locked_until) > datetime.utcnow():
        time.sleep(0.3)  # Penalty delay
        return jsonify({"error": "Account locked"}), 423

    pw_hash = hash_password(password)
    if not hmac.compare_digest(pw_hash, user["password_hash"]):
        # Increment failed attempts
        new_fail = user["failed_attempts"] + 1
        lock_time = None
        if new_fail >= 5:
            lock_time = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
        g.db.execute("""
            UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?
        """, (new_fail, lock_time, user["id"]))
        g.db.commit()
        time.sleep(random.uniform(0.08, 0.15))
        return jsonify({"error": "Invalid credentials"}), 401

    # Success
    g.db.execute("""
        UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ?
        WHERE id = ?
    """, (datetime.utcnow().isoformat(), user["id"]))
    g.db.commit()

    access, refresh = generate_tokens(user["id"], user["role"])
    return jsonify({
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "expires_in": 900,
        "role": user["role"],
    })

@app.route("/api/user/profile", methods=["GET"])
@token_required()
def profile():
    """Returns user profile. Medium weight."""
    user_id = g.current_user["sub"]
    user = g.db.execute("SELECT id, username, role, created_at, api_quota FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Simulate some processing
    time.sleep(random.uniform(0.01, 0.04))

    files = g.db.execute("SELECT COUNT(*) as c FROM files WHERE owner_id = ?", (user_id,)).fetchone()
    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "created_at": user["created_at"],
        "quota_remaining": user["api_quota"],
        "files_owned": files["c"],
    })

@app.route("/api/files/upload", methods=["POST"])
@token_required()
def upload_file():
    """File upload with simulated AV scan. Heavy, slow, CPU-bound."""
    user_id = g.current_user["sub"]

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    # Check quota
    user = g.db.execute("SELECT api_quota FROM users WHERE id = ?", (user_id,)).fetchone()
    if user["api_quota"] <= 0:
        return jsonify({"error": "Quota exceeded"}), 429

    # Save file
    safe_name = secrets.token_hex(16) + os.path.splitext(file.filename)[1]
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
    file.save(file_path)

    file_size = os.path.getsize(file_path)
    checksum = hashlib.sha256(open(file_path, "rb").read()).hexdigest()

    # Simulate AV scan (heavy operation)
    scan_status, scan_duration = simulate_av_scan(file_path)

    # Simulate encryption for large files
    encrypted = 1 if file_size > 5 * 1024 * 1024 else 0
    if encrypted:
        time.sleep(0.1)  # Extra processing for encryption

    g.db.execute("""
        INSERT INTO files (owner_id, filename, stored_name, file_size, content_type, checksum, encrypted, scan_status, scan_duration_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, file.filename, safe_name, file_size, file.content_type, checksum, encrypted, scan_status, scan_duration))

    g.db.execute("UPDATE users SET api_quota = api_quota - 1 WHERE id = ?", (user_id,))
    g.db.commit()

    return jsonify({
        "message": "File uploaded",
        "filename": file.filename,
        "size": file_size,
        "scan_status": scan_status,
        "scan_duration_ms": scan_duration,
        "encrypted": bool(encrypted),
    }), 201

@app.route("/api/files/list", methods=["GET"])
@token_required()
def list_files():
    """List user files. Light but variable response size."""
    user_id = g.current_user["sub"]
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    per_page = min(per_page, 100)

    offset = (page - 1) * per_page
    files = g.db.execute("""
        SELECT id, filename, file_size, content_type, upload_time, scan_status
        FROM files WHERE owner_id = ? ORDER BY upload_time DESC LIMIT ? OFFSET ?
    """, (user_id, per_page, offset)).fetchall()

    total = g.db.execute("SELECT COUNT(*) as c FROM files WHERE owner_id = ?", (user_id,)).fetchone()["c"]

    time.sleep(random.uniform(0.005, 0.02))  # Small DB query delay

    return jsonify({
        "files": [dict(f) for f in files],
        "total": total,
        "page": page,
        "per_page": per_page,
    })

@app.route("/api/files/download/<int:file_id>", methods=["GET"])
@token_required()
def download_file(file_id):
    """File download. Simulated bandwidth throttling."""
    user_id = g.current_user["sub"]

    file_meta = g.db.execute("""
        SELECT * FROM files WHERE id = ? AND owner_id = ?
    """, (file_id, user_id)).fetchone()

    if not file_meta:
        return jsonify({"error": "File not found"}), 404

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file_meta["stored_name"])
    if not os.path.exists(file_path):
        return jsonify({"error": "File missing from storage"}), 500

    # Simulate decryption delay for encrypted files
    if file_meta["encrypted"]:
        time.sleep(0.05)

    # Simulate bandwidth throttling for large files
    file_size = file_meta["file_size"]
    if file_size > 10 * 1024 * 1024:
        time.sleep(0.2)

    return send_file(file_path, as_attachment=True, download_name=file_meta["filename"])

@app.route("/api/search", methods=["POST"])
@token_required()
def search():
    """Search across files and audit logs. Variable complexity based on query."""
    data = request.get_json(silent=True) or {}
    query = data.get("q", "").strip()
    scope = data.get("scope", "files")  # files, logs, all

    if not query or len(query) < 2:
        return jsonify({"error": "Query too short"}), 400

    results = {"files": [], "logs": []}

    if scope in ("files", "all"):
        # Simulated heavy search — LIKE query on filename
        pattern = f"%{query}%"
        files = g.db.execute("""
            SELECT id, filename, file_size, upload_time FROM files
            WHERE filename LIKE ? ORDER BY upload_time DESC LIMIT 50
        """, (pattern,)).fetchall()
        results["files"] = [dict(f) for f in files]

    if scope in ("logs", "all"):
        # Even heavier — full audit log scan
        pattern = f"%{query}%"
        logs = g.db.execute("""
            SELECT id, action, resource, timestamp, success FROM audit_logs
            WHERE resource LIKE ? OR details LIKE ?
            ORDER BY timestamp DESC LIMIT 100
        """, (pattern, pattern)).fetchall()
        results["logs"] = [dict(l) for l in logs]
        # Heavy query penalty
        time.sleep(random.uniform(0.05, 0.2))

    return jsonify({
        "query": query,
        "scope": scope,
        "results": results,
        "total": len(results["files"]) + len(results["logs"]),
    })

@app.route("/api/admin/backup", methods=["POST"])
@token_required(roles=["admin"])
def admin_backup():
    """Admin-only heavy operation. Very slow, high resource usage."""
    backup_info = simulate_db_backup()

    g.db.execute("""
        INSERT INTO audit_logs (user_id, action, resource, success, details)
        VALUES (?, 'ADMIN_BACKUP', 'database', 1, ?)
    """, (g.current_user["sub"], json.dumps(backup_info)))
    g.db.commit()

    return jsonify({
        "message": "Backup completed",
        "backup": backup_info,
        "triggered_by": g.current_user["sub"],
    })

@app.route("/api/admin/users", methods=["GET"])
@token_required(roles=["admin"])
def admin_list_users():
    """Admin endpoint returning large dataset."""
    users = g.db.execute("""
        SELECT id, username, role, created_at, last_login, failed_attempts, api_quota
        FROM users ORDER BY created_at DESC
    """).fetchall()

    time.sleep(random.uniform(0.03, 0.08))  # Large result set processing

    return jsonify({
        "users": [dict(u) for u in users],
        "count": len(users),
    })

@app.route("/api/admin/audit", methods=["GET"])
@token_required(roles=["admin"])
def admin_audit():
    """Admin audit log viewer. Very large potential response."""
    limit = request.args.get("limit", 100, type=int)
    limit = min(limit, 1000)

    logs = g.db.execute("""
        SELECT a.*, u.username FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.timestamp DESC LIMIT ?
    """, (limit,)).fetchall()

    time.sleep(random.uniform(0.05, 0.15))

    return jsonify({
        "logs": [dict(l) for l in logs],
        "count": len(logs),
    })

@app.route("/api/metrics", methods=["GET"])
def metrics():
    """Exposes internal metrics for external monitoring."""
    db = get_db()
    total_users = db.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
    total_files = db.execute("SELECT COUNT(*) as c FROM files").fetchone()["c"]
    total_logs = db.execute("SELECT COUNT(*) as c FROM audit_logs").fetchone()["c"]

    recent_errors = db.execute("""
        SELECT COUNT(*) as c FROM audit_logs
        WHERE success = 0 AND timestamp > datetime('now', '-1 hour')
    """).fetchone()["c"]

    return jsonify({
        "users": total_users,
        "files": total_files,
        "audit_logs": total_logs,
        "recent_errors_1h": recent_errors,
        "memory_usage_mb": round(random.uniform(120, 340), 1),
        "cpu_load": round(random.uniform(0.1, 0.5), 2),
        "active_sessions": random.randint(1, 20),
    })

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print("  SecureFileVault — SENTIO Phase 2 Target")
    print("  Endpoints:")
    print("    POST /api/auth/register        — Register user")
    print("    POST /api/auth/login           — Login (get JWT)")
    print("    GET  /api/user/profile         — User profile")
    print("    POST /api/files/upload         — Upload + AV scan")
    print("    GET  /api/files/list           — List files")
    print("    GET  /api/files/download/<id>  — Download file")
    print("    POST /api/search               — Search (heavy)")
    print("    POST /api/admin/backup         — Admin backup (slow)")
    print("    GET  /api/admin/users          — List all users")
    print("    GET  /api/admin/audit          — Audit logs")
    print("    GET  /api/health               — Health check")
    print("    GET  /api/metrics              — Internal metrics")
    print("=" * 60)
    print("  Default admin: username=admin, password=admin123")
    print("  Running on http://127.0.0.1:5001")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5001, debug=False)
