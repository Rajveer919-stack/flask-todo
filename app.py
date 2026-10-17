# ========== IMPORTS ==========
import os
import sqlite3
from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Session ko safe rakhne ki secret key (asli deploy mein environment variable se aani chahiye)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")
DB_NAME = "todo.db"


# ========== 1. DATABASE ==========
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    # users table: username unique hoga
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    # tasks table: har task kisi user ka hai (user_id)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            done INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


# ========== 2. HOME PAGE (sirf login wale user ke liye) ==========
@app.route("/")
def home():
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    tasks = conn.execute(
        "SELECT * FROM tasks WHERE user_id = ?", (session["user_id"],)
    ).fetchall()
    conn.close()
    return render_template("index.html", tasks=tasks, username=session["username"])


# ========== 3. REGISTER ==========
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or len(password) < 6:
            flash("Username likho aur password kam se kam 6 character ka rakho.")
            return redirect("/register")

        # Password seedha save nahi karte, hash banake save karte hain
        hashed = generate_password_hash(password)

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed),
            )
            conn.commit()
            conn.close()
        except sqlite3.IntegrityError:
            flash("Ye username pehle se liya hua hai.")
            return redirect("/register")

        flash("Account ban gaya! Ab login karo.")
        return redirect("/login")

    return render_template("register.html")


# ========== 4. LOGIN ==========
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        # Hash se password match karo
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect("/")

        flash("Username ya password galat hai.")
        return redirect("/login")

    return render_template("login.html")


# ========== 5. LOGOUT ==========
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ========== 6. TASK ADD ==========
@app.route("/add", methods=["POST"])
def add():
    if "user_id" not in session:
        return redirect("/login")

    title = request.form["title"].strip()
    if title:
        conn = get_db()
        conn.execute(
            "INSERT INTO tasks (user_id, title) VALUES (?, ?)",
            (session["user_id"], title),
        )
        conn.commit()
        conn.close()
    return redirect("/")


# ========== 7. TASK DONE / UNDONE (sirf apna task) ==========
@app.route("/toggle/<int:task_id>")
def toggle(task_id):
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    conn.execute(
        "UPDATE tasks SET done = 1 - done WHERE id = ? AND user_id = ?",
        (task_id, session["user_id"]),
    )
    conn.commit()
    conn.close()
    return redirect("/")


# ========== 8. TASK DELETE (sirf apna task) ==========
@app.route("/delete/<int:task_id>")
def delete(task_id):
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    conn.execute(
        "DELETE FROM tasks WHERE id = ? AND user_id = ?",
        (task_id, session["user_id"]),
    )
    conn.commit()
    conn.close()
    return redirect("/")


# ========== 9. APP CHALANA ==========
if __name__ == "__main__":
    init_db()
    app.run(debug=True)