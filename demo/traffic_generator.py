"""
Traffic Generator — Simulates realistic user behavior against SecureFileVault.
Run this in a separate terminal while SENTIO is baselining.
"""
import requests
import random
import time
import string
import threading

BASE_URL = "http://127.0.0.1:5001"

def random_string(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

def register_and_login():
    """Register a random user and return tokens."""
    username = f"user_{random_string()}"
    password = f"pass_{random_string(10)}"

    requests.post(f"{BASE_URL}/api/auth/register", json={
        "username": username, "password": password
    }, timeout=5)

    resp = requests.post(f"{BASE_URL}/api/auth/login", json={
        "username": username, "password": password
    }, timeout=5)

    if resp.status_code == 200:
        return resp.json()["access_token"]
    return None

def normal_user_session(token):
    """Simulates a normal user workflow."""
    headers = {"Authorization": f"Bearer {token}"}

    # Check profile
    requests.get(f"{BASE_URL}/api/user/profile", headers=headers, timeout=5)
    time.sleep(random.uniform(0.5, 2.0))

    # Upload a small file
    files = {"file": (f"doc_{random_string()}.txt", b"A" * random.randint(100, 5000))}
    requests.post(f"{BASE_URL}/api/files/upload", files=files, headers=headers, timeout=10)
    time.sleep(random.uniform(1.0, 3.0))

    # List files
    requests.get(f"{BASE_URL}/api/files/list", headers=headers, timeout=5)
    time.sleep(random.uniform(0.3, 1.0))

    # Search
    requests.post(f"{BASE_URL}/api/search", json={
        "q": random_string(3), "scope": "files"
    }, headers=headers, timeout=5)
    time.sleep(random.uniform(0.5, 1.5))

    # Health check (unauthenticated)
    requests.get(f"{BASE_URL}/api/health", timeout=3)

def admin_workflow():
    """Simulates admin activity."""
    resp = requests.post(f"{BASE_URL}/api/auth/login", json={
        "username": "admin", "password": "admin123"
    }, timeout=5)

    if resp.status_code != 200:
        return

    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # View users
    requests.get(f"{BASE_URL}/api/admin/users", headers=headers, timeout=5)
    time.sleep(random.uniform(1.0, 2.0))

    # View audit logs
    requests.get(f"{BASE_URL}/api/admin/audit?limit=50", headers=headers, timeout=5)
    time.sleep(random.uniform(1.0, 2.0))

    # Trigger backup (heavy, slow — do rarely)
    if random.random() < 0.1:
        requests.post(f"{BASE_URL}/api/admin/backup", headers=headers, timeout=10)

    # Metrics
    requests.get(f"{BASE_URL}/api/metrics", timeout=3)

def run_session():
    """One complete user session."""
    try:
        token = register_and_login()
        if token:
            normal_user_session(token)
    except Exception as e:
        print(f"Session error: {e}")

def main():
    print("=" * 50)
    print("  SENTIO Traffic Generator")
    print("  Simulating realistic load against SecureFileVault")
    print("  Press Ctrl+C to stop")
    print("=" * 50)

    session_count = 0
    while True:
        # Spawn 1-3 user sessions
        threads = []
        for _ in range(random.randint(1, 3)):
            t = threading.Thread(target=run_session)
            t.start()
            threads.append(t)

        # Occasionally do admin work
        if random.random() < 0.15:
            t = threading.Thread(target=admin_workflow)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        session_count += len(threads)
        print(f"  Sessions completed: {session_count}", end="\r")

        # Pause between bursts
        time.sleep(random.uniform(2.0, 5.0))

if __name__ == "__main__":
    main()
