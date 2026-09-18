import sqlite3
import os
from flask import Flask, request, session, redirect, url_for, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Correcao B: Secret Key via variavel de ambiente com fallback explicito
_secret_key = os.environ.get("TASKFLOW_SECRET_KEY")
if not _secret_key:
    raise RuntimeError("Variavel de ambiente TASKFLOW_SECRET_KEY nao foi definida.")
app.config["SECRET_KEY"] = _secret_key

DATABASE = "taskflow.db"

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                done INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        # Correcao C: Senha armazenada utilizando hash seguro (Werkzeug)
        try:
            db.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                ("admin", generate_password_hash("admin123"))
            )
        except sqlite3.IntegrityError:
            pass
        db.commit()

init_db()

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("tasks"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Correcao A: Query parametrizada para prevenir SQL Injection
        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        # Correcao C: Verificacao segura do hash da senha
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("tasks"))
        else:
            error = "Credenciais invalidas."

    return f"""
    <h1>TaskFlow - Login</h1>
    <p style="color:red">{error if error else ''}</p>
    <form method="post">
        <label>Usuario: <input type="text" name="username"></label><br>
        <label>Senha: <input type="password" name="password"></label><br>
        <input type="submit" value="Entrar">
    </form>
    """

@app.route("/tasks")
def tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))

    search = request.args.get("q", "")
    db = get_db()

    # Correcao A: Query parametrizada com LIKE seguro
    if search:
        like_pattern = f"%{search}%"
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ? AND title LIKE ?",
            (session["user_id"], like_pattern)
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM tasks WHERE user_id = ?",
            (session["user_id"],)
        ).fetchall()

    items = ""
    for row in rows:
        items += f"<li><b>{row['title']}</b> - {row['description']}</li>"

    return f"""
    <h1>Minhas Tarefas ({session['username']})</h1>
    <form method="get"><input type="text" name="q"><input type="submit" value="Buscar"></form>
    <ul>{items}</ul>
    <a href="{url_for('new_task')}">Nova Tarefa</a> | <a href="{url_for('logout')}">Sair</a>
    """

@app.route("/tasks/new", methods=["GET", "POST"])
def new_task():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        db = get_db()
        db.execute(
            "INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)",
            (session["user_id"], title, description)
        )
        db.commit()
        return redirect(url_for("tasks"))

    return """
    <h1>Nova Tarefa</h1>
    <form method="post">
        Title: <input type="text" name="title"><br>
        Desc: <textarea name="description"></textarea><br>
        <input type="submit" value="Salvar">
    </form>
    """

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
