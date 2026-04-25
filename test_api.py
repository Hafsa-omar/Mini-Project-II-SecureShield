"""
SecureShield — Automatic API Test
HOW TO RUN:
  Terminal 1:  python app.py        (keep this running)
  Terminal 2:  python test_api.py
"""

import requests

BASE = "http://127.0.0.1:5000"

# ── Check server is running before anything else ──────────────
try:
    requests.get(BASE, timeout=3)
except requests.exceptions.ConnectionError:
    print("\n ERROR: Flask server is not running!")
    print(" Open a NEW terminal and run:  python app.py")
    print(" Then run this script again.\n")
    exit()


def test(label, method, url, body=None, token=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    if   method == "POST":   res = requests.post(url,   json=body, headers=headers)
    elif method == "GET":    res = requests.get(url,               headers=headers)
    elif method == "DELETE": res = requests.delete(url,            headers=headers)

    try:
        data = res.json()
    except Exception:
        data = res.text   # show raw text if JSON fails

    print(f"\n  [{res.status_code}]  {label}")
    print(f"         {data}")
    return data, res.status_code


# ══════════════════════════════════════════════════════════════
print("\n══════════════════════════════════════════════════════")
print("             SecureShield API Test")
print("══════════════════════════════════════════════════════")

# ── PART 1: Register ──────────────────────────────────────────
print("\n── PART 1: Register Users ──")

test("Register alice (user)",
     "POST", f"{BASE}/register",
     body={"username": "alice", "password": "pass123", "role": "user"})

test("Register admin1 (admin)",
     "POST", f"{BASE}/register",
     body={"username": "admin1", "password": "admin123", "role": "admin"})

test("Register alice again → should get 409 error",
     "POST", f"{BASE}/register",
     body={"username": "alice", "password": "pass123", "role": "user"})

# ── PART 2: Login ─────────────────────────────────────────────
print("\n── PART 2: Login ──")

data, _ = test("Login as alice",
               "POST", f"{BASE}/login",
               body={"username": "alice", "password": "pass123"})
user_token = data.get("token", "") if isinstance(data, dict) else ""

data, _ = test("Login as admin1",
               "POST", f"{BASE}/login",
               body={"username": "admin1", "password": "admin123"})
admin_token = data.get("token", "") if isinstance(data, dict) else ""

test("Login with wrong password → should get 401",
     "POST", f"{BASE}/login",
     body={"username": "alice", "password": "WRONG"})

# ── PART 3: Profile ───────────────────────────────────────────
print("\n── PART 3: Profile (login required) ──")

test("GET /profile as alice → should work",
     "GET", f"{BASE}/profile", token=user_token)

test("GET /profile with no token → should get 401",
     "GET", f"{BASE}/profile")

# ── PART 4: Admin-only delete ─────────────────────────────────
print("\n── PART 4: Delete User (admin only) ──")

test("alice tries DELETE /user/1 → should get 403 Forbidden",
     "DELETE", f"{BASE}/user/1", token=user_token)

# ── PART 5: Logout & token revocation ────────────────────────
print("\n── PART 5: Logout & Token Revocation ──")

test("Logout alice (revoke her token)",
     "POST", f"{BASE}/logout", token=user_token)

test("Alice's token used after logout → should get 401",
     "GET", f"{BASE}/profile", token=user_token)

# ── PART 6: Tampered token ────────────────────────────────────
print("\n── PART 6: Tampered JWT Test ──")

fake_token = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJ1c2VybmFtZSI6ImFsaWNlIiwicm9sZSI6ImFkbWluIn0"
    ".FAKESIGNATURE123"
)
test("Tampered token (role changed to admin) → should get 401",
     "DELETE", f"{BASE}/user/1", token=fake_token)

# ── PART 7: Admin deletes a user ─────────────────────────────
print("\n── PART 7: Admin Deletes a User ──")

test("Admin deletes alice (ID 1) → should work",
     "DELETE", f"{BASE}/user/1", token=admin_token)

print("\n══════════════════════════════════════════════════════")
print("  Done! Check security.log for the 403 log entry.")
print("══════════════════════════════════════════════════════\n")
