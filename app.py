from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Optional

from flask import (
    Flask, render_template, request, redirect, url_for, flash, session
)
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.db"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "troque-essa-chave-em-producao")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.commit()


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM users WHERE email = ?", (email.lower().strip(),))
        return cur.fetchone()


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    with get_db() as conn:
        cur = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return cur.fetchone()


@app.before_request
def ensure_db() -> None:
    init_db()


@app.route("/")
def index():
    user = None
    if "user_id" in session:
        user = get_user_by_id(session["user_id"])
        # se usuário foi removido do banco, limpa sessão
        if user is None:
            session.pop("user_id", None)
    return render_template("index.html", user=user)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        # validações básicas
        if not name or not email or not password or not confirm:
            flash("Preencha todos os campos.", "error")
            return redirect(url_for("register"))

        if "@" not in email or "." not in email:
            flash("E-mail inválido.", "error")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("A senha deve ter no mínimo 6 caracteres.", "error")
            return redirect(url_for("register"))

        if password != confirm:
            flash("As senhas não conferem.", "error")
            return redirect(url_for("register"))

        if get_user_by_email(email):
            flash("Esse e-mail já está cadastrado.", "error")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                    (name, email, password_hash),
                )
                conn.commit()
        except sqlite3.IntegrityError:
            flash("Esse e-mail já está cadastrado.", "error")
            return redirect(url_for("register"))

        flash("Conta criada com sucesso! Agora faça login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Informe e-mail e senha.", "error")
            return redirect(url_for("login"))

        user = get_user_by_email(email)
        if not user:
            flash("E-mail ou senha inválidos.", "error")
            return redirect(url_for("login"))

        if not check_password_hash(user["password_hash"], password):
            flash("E-mail ou senha inválidos.", "error")
            return redirect(url_for("login"))

        session["user_id"] = user["id"]
        flash(f"Bem-vindo, {user['name']}!", "success")
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Você saiu da conta.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
