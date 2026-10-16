import re, sqlite3, secrets
import bcrypt
from flask import Flask, request, session, redirect, render_template_string, flash

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
DB = "users.db"

def db():
    return sqlite3.connect(DB)

with db() as c:
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, "
              "username TEXT UNIQUE NOT NULL, password_hash BLOB NOT NULL)")

PAGE = """
<!doctype html><title>Secure Login</title>
<body style="font-family:sans-serif;max-width:340px;margin:60px auto">
{% for m in get_flashed_messages() %}<p style="color:#b00">{{ m }}</p>{% endfor %}
<h2>{{ title }}</h2>
{% if user %}
  <p>Hello, {{ user }}!</p>
  <form method="post" action="/logout"><button>Log out</button></form>
{% else %}
  <form method="post">
    <input name="username" placeholder="Username" required><br><br>
    <input name="password" type="password" placeholder="Password" required><br><br>
    <button>{{ title }}</button>
  </form>
  <p><a href="{{ other[0] }}">{{ other[1] }}</a></p>
{% endif %}
"""

@app.route("/")
def home():
    if "user" in session:
        return render_template_string(PAGE, title="Dashboard", user=session["user"])
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form["username"].strip()
        p = request.form["password"]
        if not re.fullmatch(r"\w{3,20}", u):
            flash("Username: 3-20 letters, numbers or underscore.")
        elif not 8 <= len(p) <= 72:
            flash("Password must be 8-72 characters.")
        else:
            try:
                with db() as c:  # ? placeholders prevent SQL injection
                    c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                              (u, bcrypt.hashpw(p.encode(), bcrypt.gensalt())))
                return redirect("/login")
            except sqlite3.IntegrityError:
                flash("Username already taken.")
    return render_template_string(PAGE, title="Register", user=None, other=("/login", "Have an account? Log in"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, p = request.form["username"].strip(), request.form["password"]
        row = db().execute("SELECT password_hash FROM users WHERE username = ?", (u,)).fetchone()
        if row and bcrypt.checkpw(p.encode(), row[0]):
            session.clear()
            session["user"] = u
            return redirect("/")
        flash("Wrong username or password.")
    return render_template_string(PAGE, title="Log in", user=None, other=("/register", "New here? Register"))

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run()
