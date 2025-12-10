from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = "change_this_to_a_random_secret_key"

# ----------------- DATABASE SETUP -----------------

DB_NAME = "incomix.db"


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    # Users table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        """
    )

    # Income entries table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS income (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            source TEXT NOT NULL,
            amount REAL NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """
    )

    conn.commit()
    conn.close()


# Initialize DB if not present
if not os.path.exists(DB_NAME):
    init_db()
else:
    # ensure tables exist even if db file exists
    init_db()

# ----------------- AUTH HELPERS -----------------


def current_user():
    if "user_id" in session:
        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        conn.close()
        return user
    return None


def login_required(view_func):
    from functools import wraps

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped_view


# ----------------- ROUTES -----------------


@app.route("/")
def index():
    user = current_user()
    return render_template("index.html", user=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm", "").strip()

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Username already exists. Choose another.", "danger")
            conn.close()
            return redirect(url_for("register"))

        conn.close()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            flash("Logged in successfully!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    user = current_user()
    conn = get_db_connection()

    if request.method == "POST":
        source = request.form.get("source", "").strip()
        amount = request.form.get("amount", "").strip()

        if not source or not amount:
            flash("Source and amount are required.", "danger")
            conn.close()
            return redirect(url_for("dashboard"))

        try:
            amount_value = float(amount)
        except ValueError:
            flash("Amount must be a number.", "danger")
            conn.close()
            return redirect(url_for("dashboard"))

        conn.execute(
            "INSERT INTO income (user_id, source, amount) VALUES (?, ?, ?)",
            (user["id"], source, amount_value),
        )
        conn.commit()
        flash("Income entry added.", "success")

    incomes = conn.execute(
        "SELECT * FROM income WHERE user_id = ? ORDER BY created_at DESC",
        (user["id"],),
    ).fetchall()

    total_income = conn.execute(
        "SELECT SUM(amount) as total FROM income WHERE user_id = ?",
        (user["id"],),
    ).fetchone()["total"]

    conn.close()

    if total_income is None:
        total_income = 0

    return render_template(
        "dashboard.html", user=user, incomes=incomes, total_income=total_income
    )


if __name__ == "__main__":
    app.run(debug=True)