import sqlite3
import datetime
import logging
from functools import wraps

import jwt
from flask import Flask, request, jsonify, g, send_from_directory
from flask_bcrypt import Bcrypt

# ============================================================
#  App Setup
# ============================================================

app = Flask(__name__)
bcrypt = Bcrypt(app)

SECRET_KEY = "my-secret-key-change-this-in-production"
DATABASE   = "users.db"

# Stores revoked tokens so logged-out users can't reuse them
blacklisted_tokens = set()


# ============================================================
#  Security Log  (writes 403 attempts to security.log)
# ============================================================

logger = logging.getLogger("security")
logger.setLevel(logging.WARNING)
logger.addHandler(logging.FileHandler("security.log"))


# ============================================================
#  Database  (one connection per request, auto-closed after)
# ============================================================

def get_db():
    # Reuse the same connection within a single request
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")  # prevents locking
    return g.db


@app.teardown_appcontext
def close_db(error):
    # Flask calls this automatically at the end of every request
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    UNIQUE NOT NULL,
                password TEXT    NOT NULL,
                role     TEXT    NOT NULL DEFAULT 'user'
            )
        """)
        db.commit()


# ============================================================
#  Decorators  (reusable checks we put above routes)
# ============================================================

def login_required(f):
    """
    Checks that the request has a valid JWT token.
    If OK, saves the user info in g.user for the route to use.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):

        # 1. Get the token from the Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            logger.warning(
                f"{datetime.datetime.now()} | 401 NO TOKEN | "
                f"Tried: {request.method} {request.path}"
            )
            return jsonify({"error": "No token provided."}), 401

        token = auth_header.split(" ")[1]

        # 2. Reject blacklisted (logged-out) tokens
        if token in blacklisted_tokens:
            logger.warning(
                f"{datetime.datetime.now()} | 401 REVOKED TOKEN | "
                f"Tried: {request.method} {request.path}"
            )
            return jsonify({"error": "Token was revoked. Please log in again."}), 401

        # 3. Verify the token signature and expiry
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            g.user  = payload   # e.g. {"username": "alice", "role": "user"}
            g.token = token
        except jwt.ExpiredSignatureError:
            logger.warning(
                f"{datetime.datetime.now()} | 401 EXPIRED TOKEN | "
                f"Tried: {request.method} {request.path}"
            )
            return jsonify({"error": "Token expired. Please log in again."}), 401
        except jwt.InvalidTokenError:
            logger.warning(
                f"{datetime.datetime.now()} | 401 INVALID TOKEN | "
                f"Tried: {request.method} {request.path}"
            )
            return jsonify({"error": "Invalid token. Signature check failed."}), 401

        return f(*args, **kwargs)

    return wrapper


def admin_required(f):
    """
    Must be used AFTER @login_required.
    Allows only users whose role is 'admin'.
    Logs every failed attempt to security.log.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):

        if g.user["role"] != "admin":
            logger.warning(
                f"{datetime.datetime.now()} | 403 FORBIDDEN | "
                f"User='{g.user['username']}' Role='{g.user['role']}' | "
                f"Tried: {request.method} {request.path}"
            )
            return jsonify({"error": "Admins only."}), 403

        return f(*args, **kwargs)

    return wrapper


# ============================================================
#  Routes  –  Public (no token needed)
# ============================================================

@app.route("/", methods=["GET"])
def home():
    """Serve the visual API tester page."""
    return send_from_directory(".", "test.html")


@app.route("/register", methods=["POST"])
def register():
    """Create a new account. Password is hashed with bcrypt before saving."""
    data     = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role     = data.get("role", "user").lower()

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    if role not in ("user", "admin"):
        return jsonify({"error": "Role must be 'user' or 'admin'."}), 400

    # Hash the password — bcrypt adds a random salt automatically
    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    try:
        db = get_db()
        db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed_password, role)
        )
        db.commit()
        return jsonify({"message": f"User '{username}' registered successfully."}), 201

    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already taken."}), 409


@app.route("/login", methods=["POST"])
def login():
    """Check credentials, then return a signed JWT token."""
    data     = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    db   = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not user or not bcrypt.check_password_hash(user["password"], password):
        logger.warning(
            f"{datetime.datetime.now()} | 401 FAILED LOGIN | "
            f"Username='{username}' | IP: {request.remote_addr}"
        )
        return jsonify({"error": "Wrong username or password."}), 401

    token = jwt.encode(
        {
            "username": user["username"],
            "role":     user["role"],
            "exp":      datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        },
        SECRET_KEY,
        algorithm="HS256"
    )

    return jsonify({"token": token, "role": user["role"]}), 200


# ============================================================
#  Routes  –  Protected (valid token required)
# ============================================================

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    """Add the current token to the blacklist so it can't be used again."""
    blacklisted_tokens.add(g.token)
    return jsonify({"message": "Logged out. Token revoked."}), 200


@app.route("/profile", methods=["GET"])
@login_required
def profile():
    """Return the logged-in user's profile. Both 'user' and 'admin' can access this."""
    db   = get_db()
    user = db.execute(
        "SELECT id, username, role FROM users WHERE username = ?",
        (g.user["username"],)
    ).fetchone()

    return jsonify({
        "id":       user["id"],
        "username": user["username"],
        "role":     user["role"]
    }), 200


# ============================================================
#  Routes  –  Admin only
# ============================================================

@app.route("/user/<int:user_id>", methods=["DELETE"])
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user by ID. Only admins can do this."""
    db   = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()

    if not user:
        return jsonify({"error": f"No user found with ID {user_id}."}), 404

    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()

    return jsonify({"message": f"User '{user['username']}' deleted."}), 200


# ============================================================
#  Start the app
# ============================================================

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
