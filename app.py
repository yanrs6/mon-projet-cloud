import os
import secrets
import sqlite3
import hmac

from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, g, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", secrets.token_hex(32)
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "app.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    db.commit()
    db.close()


@app.before_request
def protect_forms():
    if request.method == "POST":
        token = session.get("csrf_token")
        submitted = request.form.get("csrf_token", "")

        if not token or not hmac.compare_digest(token, submitted):
            abort(400, description="Formulaire invalide. Recharge la page.")


@app.context_processor
def inject_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    return {"csrf_token": session["csrf_token"]}


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Connecte-toi pour accéder à cette page.")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(username) > 30:
            flash("Le nom d'utilisateur doit contenir de 3 à 30 caractères.")
            return render_template("register.html")

        if not username.isalnum():
            flash("Utilise uniquement des lettres et des chiffres dans le nom.")
            return render_template("register.html")

        if len(password) < 12:
            flash("Le mot de passe doit contenir au moins 12 caractères.")
            return render_template("register.html")

        password_hash = generate_password_hash(password)

        try:
            db = get_db()
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Ce nom d'utilisateur existe déjà.")
            return render_template("register.html")

        flash("Compte créé ! Tu peux maintenant te connecter.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user is None or not check_password_hash(
            user["password_hash"], password
        ):
            flash("Nom d'utilisateur ou mot de passe incorrect.")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["csrf_token"] = secrets.token_hex(32)

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    notes = get_db().execute(
        "SELECT id, content FROM notes WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],)
    ).fetchall()

    return render_template("dashboard.html", notes=notes)


@app.route("/notes", methods=["POST"])
@login_required
def add_note():
    content = request.form.get("content", "").strip()

    if not content or len(content) > 1000:
        flash("La note doit contenir entre 1 et 1000 caractères.")
    else:
        db = get_db()
        db.execute(
            "INSERT INTO notes (user_id, content) VALUES (?, ?)",
            (session["user_id"], content)
        )
        db.commit()
        flash("Note enregistrée.")

    return redirect(url_for("dashboard"))


@app.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def delete_note(note_id):
    db = get_db()
    db.execute(
        "DELETE FROM notes WHERE id = ? AND user_id = ?",
        (note_id, session["user_id"])
    )
    db.commit()

    flash("Note supprimée.")
    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("Tu es déconnecté.")
    return redirect(url_for("index"))


init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
   