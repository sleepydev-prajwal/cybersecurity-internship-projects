"""
Secure Login System
Task 4 - Flask web app with:
  - bcrypt hashed passwords (never stored in plain text)
  - input validation
  - SQL injection protection (parameterized queries)
  - session management with logout
Run:  python secure_login_app.py   then open http://127.0.0.1:5000
"""

import os
import re
import sqlite3

import bcrypt
from flask import Flask, redirect, render_template_string, request, session, url_for

app = Flask(__name__)
app.secret_key = os.urandom(24)  # random key, signs the session cookie
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE="Lax",  # basic CSRF protection
)

DB_FILE = "users.db"
USERNAME_RULE = re.compile(r"^[A-Za-z0-9_]{3,20}$")  # only safe characters


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS users (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT UNIQUE NOT NULL,
                   password_hash BLOB NOT NULL
               )"""
        )


PAGE = """
<!doctype html>
<title>Secure Login</title>
<body style="font-family:Arial;max-width:380px;margin:60px auto;">
<h2>{{ title }}</h2>
{% if message %}<p style="color:{{ color }}">{{ message }}</p>{% endif %}
{% if form %}
<form method="post">
  <input name="username" placeholder="Username" required style="width:100%;padding:8px;margin:6px 0"><br>
  <input name="password" type="password" placeholder="Password" required style="width:100%;padding:8px;margin:6px 0"><br>
  <button style="padding:8px 16px">{{ title }}</button>
</form>
<p><a href="{{ other_url }}">{{ other_text }}</a></p>
{% endif %}
{% if user %}
<p>Welcome, <b>{{ user }}</b>! You are logged in.</p>
<a href="/logout">Logout</a>
{% endif %}
</body>
"""


@app.route("/")
def home():
    return redirect(url_for("dashboard" if "user" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Input validation
        if not USERNAME_RULE.match(username):
            message = "Username: 3-20 characters, letters/numbers/underscore only."
        elif len(password) < 8:
            message = "Password must be at least 8 characters."
        else:
            # Hash the password with bcrypt (salt is added automatically)
            hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
            try:
                with get_db() as conn:
                    # "?" placeholders = parameterized query = no SQL injection
                    conn.execute(
                        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                        (username, hashed),
                    )
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                message = "Username already taken."
    return render_template_string(
        PAGE, title="Register", form=True, message=message, color="red",
        other_url="/login", other_text="Already have an account? Login",
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

        # Same error for wrong username or wrong password (does not leak which one)
        if row and bcrypt.checkpw(password.encode("utf-8"), row["password_hash"]):
            session.clear()
            session["user"] = row["username"]
            return redirect(url_for("dashboard"))
        message = "Invalid username or password."
    return render_template_string(
        PAGE, title="Login", form=True, message=message, color="red",
        other_url="/register", other_text="No account? Register",
    )


@app.route("/dashboard")
def dashboard():
    if "user" not in session:  # session check = protected page
        return redirect(url_for("login"))
    return render_template_string(PAGE, title="Dashboard", user=session["user"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
