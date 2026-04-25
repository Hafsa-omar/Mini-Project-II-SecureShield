# SecureShield — Role-Based Access Control API

A secure Python Flask API that uses **JWT tokens** and **Role-Based Access Control (RBAC)** to protect routes based on user roles (Admin vs User).



## Team Members

- Fadumo Jamal Salad — 210208954
- Hafsa Omar Ismail Samatar — 210208735
- Sabreen Elmi Aidarus Gure — 210208856



## What This Project Does

This API simulates a real-world secure backend system where:
- Users can **register** and **login**
- Passwords are **never stored as plain text**
- After login, users receive a **JWT token** to access protected routes
- **Admins** can do everything users can, plus delete other users
- Logged-out tokens are **blacklisted** so they cannot be reused
- Every unauthorized access attempt is **logged** to a file



## How to Run

**1. Install dependencies:**
```bash
pip install -r requirements.txt
```

**2. Start the server:**
```bash
python app.py
```

**3. Open your browser and go to:**
```
http://127.0.0.1:5000
```



## API Endpoints

| Method | Route | Who Can Access | Description |
|--------|-------|---------------|-------------|
| POST | `/register` | Anyone | Create a new account |
| POST | `/login` | Anyone | Login and receive a JWT token |
| POST | `/logout` | Logged-in users | Revoke your token |
| GET | `/profile` | User & Admin | View your profile |
| DELETE | `/user/<id>` | Admin only | Delete a user |



## How Each Task Was Implemented

### Task 1 — Secure Password Storage
When a user registers, their password is **never saved as plain text**.  
Instead, `bcrypt` hashes and salts it before saving to the SQLite database.

```python
hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
```

What gets saved in the database looks like this:
```
$2b$12$KIxQr2TjNHPbXz1eO3Uf8uVgLmZ9A...  (unreadable)
```



### Task 2 — JWT Issuance
When a user logs in successfully, the server generates a **signed JWT token** containing the user's username and role.

```python
token = jwt.encode(
    {"username": "alice", "role": "user", "exp": <1 hour from now>},
    SECRET_KEY,
    algorithm="HS256"
)
```

The token is sent back to the user and must be included in all future requests.



### Task 3 — Token Validation
A decorator called `@login_required` is placed above protected routes.  
It checks every request for a valid, non-expired JWT token in the `Authorization` header.

```
Authorization: Bearer <your_token_here>
```

If the token is missing, expired, or tampered with — the request is rejected with a **401 error**.



### Task 4 — Role-Based Routing
Two levels of access are enforced:

- `GET /profile` → requires `@login_required` → **both User and Admin** can access
- `DELETE /user/<id>` → requires `@login_required` + `@admin_required` → **Admin only**

If a regular user tries to access the delete route, they get:
```json
{"error": "Admins only."}  →  403 Forbidden
```



### Task 5 — Token Revocation (Blacklisting)
Since JWT tokens are stateless, they cannot be truly deleted.  
When a user logs out, their token is added to an **in-memory blacklist**.

```python
blacklisted_tokens.add(g.token)
```

Any future request using that token is immediately rejected — even if it hasn't expired yet.



### Task 6 — Defensive Logging
A middleware logs every security event to `security.log` including:
- Failed login attempts (wrong password)
- Requests with no token
- Requests with revoked tokens
- Unauthorized admin route access (403)

Example log entries:
```
2026-04-25 16:22:49 | 401 FAILED LOGIN   | Username='alice' | IP: 127.0.0.1
2026-04-25 16:22:49 | 401 REVOKED TOKEN  | Tried: GET /profile
2026-04-25 16:22:49 | 403 FORBIDDEN      | User='h123' Role='user' | Tried: DELETE /user/1
```



## Report Questions

### 1. Why is Salting Necessary to Prevent Rainbow Table Attacks?

A **Rainbow Table** is a pre-computed list of common passwords and their hashes.  
Without salting, an attacker can look up a stolen hash in the table and instantly find the original password.

**Salting** adds a random string to each password before hashing it.  
This means even if two users have the same password, their hashes will be completely different.

Example:
| User | Password | Salt | Final Hash |
|------|----------|------|------------|
| alice | pass123 | xK9m | `$2b$12$xK9m...abc` |
| bob | pass123 | pL2z | `$2b$12$pL2z...xyz` |

The attacker's Rainbow Table becomes useless because it doesn't have entries for salted combinations.  
`bcrypt` automatically generates a unique salt for every password, making Rainbow Table attacks impossible.



### 2. Risks of Storing Sensitive Data Inside a JWT Payload

The JWT payload is **Base64 encoded — not encrypted**.  
Anyone who gets the token can decode it and read its contents instantly.

```
Header.Payload.Signature
```

Decoding the payload reveals everything in plain text:
```json
{"username": "alice", "role": "user", "exp": 1234567890}
```

**If you stored a password or sensitive data in the payload:**
- Anyone who intercepts the token can read it
- The data is exposed in browser storage, network logs, and server logs
- Even after logout, old tokens stored by attackers still contain the data

**Rule:** Only store non-sensitive identifiers in JWT (username, role, expiry).  
Never store passwords, credit cards, personal data, or secret keys inside a JWT.



## Technologies Used

| Library | Purpose |
|---------|---------|
| Flask | Web framework |
| Flask-Bcrypt | Password hashing with bcrypt |
| PyJWT | Creating and verifying JWT tokens |
| SQLite | Local database for storing users |



## Project Structure

```
SecureShield/
├── app.py            # Main Flask application
├── requirements.txt  # Project dependencies
├── test.html         # Browser-based API tester
├── test_api.py       # Automated Python test script
├── security.log      # Security event logs (auto-created)
└── users.db          # SQLite database (auto-created)
```
