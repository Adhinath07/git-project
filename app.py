#SecureVote - a small voting system built with Flask + sqlite3.

import os
import re
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("VOTING_DB", os.path.join(BASE_DIR, "voting.db"))

MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300


def load_secret_key():
    """Use SECRET_KEY from the environment, else create a persistent key file."""
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    path = os.path.join(BASE_DIR, ".secret_key")
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(secrets.token_hex(32))
    with open(path) as fh:
        return fh.read().strip()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=64 * 1024,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS elections (
    id                TEXT PRIMARY KEY,
    title             TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'draft'
                      CHECK (status IN ('draft', 'open', 'closed')),
    results_published INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL,
    opened_at         TEXT,
    closed_at         TEXT
);

CREATE TABLE IF NOT EXISTS candidates (
    id          TEXT PRIMARY KEY,
    election_id TEXT NOT NULL REFERENCES elections(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);

-- who has voted (NOT linked to the ballot they cast)
CREATE TABLE IF NOT EXISTS voters (
    election_id TEXT NOT NULL REFERENCES elections(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    voted_at    TEXT NOT NULL,
    PRIMARY KEY (election_id, user_id)
);

-- the ballots themselves; id doubles as the voter's receipt
CREATE TABLE IF NOT EXISTS ballots (
    id           TEXT PRIMARY KEY,
    election_id  TEXT NOT NULL REFERENCES elections(id) ON DELETE CASCADE,
    candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    cast_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_candidates_election ON candidates(election_id);
CREATE INDEX IF NOT EXISTS idx_ballots_election    ON ballots(election_id);
CREATE INDEX IF NOT EXISTS idx_ballots_candidate   ON ballots(candidate_id);
"""


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def new_id():
    return str(uuid.uuid4())


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    admin = db.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone()
    if not admin:
        username = os.environ.get("ADMIN_USERNAME", "admin")
        password = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(12)
        db.execute(
            "INSERT INTO users (id, username, email, password_hash, role, created_at) "
            "VALUES (?, ?, ?, ?, 'admin', ?)",
            (new_id(), username, f"{username}@localhost",
             generate_password_hash(password), now()),
        )
        db.commit()
        print("=" * 60)
        print(f" Admin account created  ->  username: {username}")
        if not os.environ.get("ADMIN_PASSWORD"):
            print(f"                            password: {password}")
            print(" (shown once - change it from the Profile page)")
        print("=" * 60)


with app.app_context():
    init_db()

DUMMY_HASH = generate_password_hash("dummy-password-for-constant-time")
FAILED_LOGINS = {}


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        expected = session.get("csrf_token")
        sent = request.form.get("csrf_token", "")
        if not expected or not secrets.compare_digest(
                sent.encode("utf-8"), expected.encode("utf-8")):
            abort(400, "Invalid or missing CSRF token. Reload the page and try again.")


@app.before_request
def load_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id:
        g.user = get_db().execute(
            "SELECT id, username, email, role, created_at FROM users WHERE id = ?",
            (user_id,)).fetchone()
        if g.user is None:
            session.clear()


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'")
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store"
    return resp


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def is_throttled(key):
    cutoff = time.time() - LOGIN_WINDOW_SECONDS
    FAILED_LOGINS[key] = [t for t in FAILED_LOGINS.get(key, []) if t > cutoff]
    return len(FAILED_LOGINS[key]) >= MAX_LOGIN_ATTEMPTS


def safe_next(target):
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return None


def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if password.isdigit() or password.isalpha():
        return "Password must mix letters with numbers or symbols."
    return None


@app.template_filter("dt")
def format_dt(value):
    return f"{value} UTC" if value else "-"

def get_election_or_404(election_id):
    election = get_db().execute(
        "SELECT * FROM elections WHERE id = ?", (election_id,)).fetchone()
    if election is None:
        abort(404)
    return election


def tally(election_id):
    """Return (rows, total_votes, turnout_percent, winners)."""
    db = get_db()
    rows = db.execute(
        """SELECT c.id, c.name, c.description, COUNT(b.id) AS votes
           FROM candidates c LEFT JOIN ballots b ON b.candidate_id = c.id
           WHERE c.election_id = ?
           GROUP BY c.id ORDER BY votes DESC, c.name COLLATE NOCASE""",
        (election_id,)).fetchall()
    total = sum(r["votes"] for r in rows)
    eligible = db.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'user'").fetchone()[0]
    turnout = round(100 * total / eligible, 1) if eligible else 0
    top = rows[0]["votes"] if rows else 0
    winners = [r["id"] for r in rows if top > 0 and r["votes"] == top]
    results = [{**dict(r), "percent": round(100 * r["votes"] / total, 1) if total else 0}
               for r in rows]
    return results, total, turnout, winners

@app.route("/")
def home():
    db = get_db()
    stats = {
        "open": db.execute("SELECT COUNT(*) FROM elections WHERE status='open'").fetchone()[0],
        "published": db.execute(
            "SELECT COUNT(*) FROM elections WHERE results_published=1").fetchone()[0],
        "voters": db.execute("SELECT COUNT(*) FROM users WHERE role='user'").fetchone()[0],
    }
    open_elections = db.execute(
        "SELECT id, title, description FROM elections WHERE status='open' "
        "ORDER BY opened_at DESC LIMIT 3").fetchall()
    return render_template("home.html", stats=stats, open_elections=open_elections)


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))
    username = email = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        errors = []
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            errors.append("Username must be 3-30 letters, numbers or underscores.")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 120:
            errors.append("Enter a valid email address.")
        pw_error = validate_password(password)
        if pw_error:
            errors.append(pw_error)
        if password != confirm:
            errors.append("Passwords do not match.")
        if not errors:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (id, username, email, password_hash, role, created_at) "
                    "VALUES (?, ?, ?, ?, 'user', ?)",
                    (new_id(), username, email, generate_password_hash(password), now()))
                db.commit()
            except sqlite3.IntegrityError:
                errors.append("That username or email is already registered.")
        if errors:
            for err in errors:
                flash(err, "error")
            return render_template("register.html", username=username, email=email), 400
        flash("Account created. You can log in now.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", username=username, email=email)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        identity = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        key = (request.remote_addr, identity.lower())
        if is_throttled(key):
            flash("Too many failed attempts. Try again in a few minutes.", "error")
            return render_template("login.html", username=identity), 429
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identity, identity.lower())).fetchone()
        ok = check_password_hash(user["password_hash"] if user else DUMMY_HASH, password)
        if user and ok:
            FAILED_LOGINS.pop(key, None)
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(safe_next(request.args.get("next")) or url_for("dashboard"))
        FAILED_LOGINS.setdefault(key, []).append(time.time())
        flash("Invalid username or password.", "error")
        return render_template("login.html", username=identity), 401
    return render_template("login.html", username="")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    if g.user["role"] == "admin":
        return redirect(url_for("admin_dashboard"))
    db = get_db()
    elections = db.execute(
        """SELECT e.id, e.title, e.status, e.results_published,
                  EXISTS(SELECT 1 FROM voters v
                         WHERE v.election_id = e.id AND v.user_id = ?) AS voted
           FROM elections e WHERE e.status IN ('open', 'closed')
           ORDER BY e.created_at DESC""", (g.user["id"],)).fetchall()
    open_pending = sum(1 for e in elections if e["status"] == "open" and not e["voted"])
    voted_count = sum(1 for e in elections if e["voted"])
    return render_template("dashboard.html", elections=elections,
                           open_pending=open_pending, voted_count=voted_count)


@app.route("/vote")
@login_required
def vote_list():
    if g.user["role"] == "admin":
        flash("Administrators manage elections and cannot vote.", "error")
        return redirect(url_for("admin_dashboard"))
    elections = get_db().execute(
        """SELECT e.id, e.title, e.description,
                  (SELECT COUNT(*) FROM candidates c WHERE c.election_id = e.id) AS n_candidates,
                  EXISTS(SELECT 1 FROM voters v
                         WHERE v.election_id = e.id AND v.user_id = ?) AS voted
           FROM elections e WHERE e.status = 'open'
           ORDER BY e.opened_at DESC""", (g.user["id"],)).fetchall()
    return render_template("vote.html", elections=elections)


@app.route("/vote/<election_id>", methods=["GET", "POST"])
@login_required
def vote(election_id):
    if g.user["role"] == "admin":
        flash("Administrators manage elections and cannot vote.", "error")
        return redirect(url_for("admin_dashboard"))
    db = get_db()
    election = get_election_or_404(election_id)
    if election["status"] != "open":
        flash("This election is not open for voting.", "error")
        return redirect(url_for("vote_list"))
    already = db.execute(
        "SELECT 1 FROM voters WHERE election_id = ? AND user_id = ?",
        (election_id, g.user["id"])).fetchone()
    if already:
        flash("You have already voted in this election.", "error")
        return redirect(url_for("vote_list"))
    candidates = db.execute(
        "SELECT id, name, description FROM candidates WHERE election_id = ? "
        "ORDER BY name COLLATE NOCASE", (election_id,)).fetchall()

    if request.method == "POST":
        candidate_id = request.form.get("candidate_id", "")
        if candidate_id not in {c["id"] for c in candidates}:
            flash("Please choose one of the listed candidates.", "error")
            return render_template("ballot.html", election=election, candidates=candidates), 400
        receipt = new_id()
        try:
            db.execute("BEGIN IMMEDIATE")
            still_open = db.execute(
                "SELECT 1 FROM elections WHERE id = ? AND status = 'open'",
                (election_id,)).fetchone()
            if not still_open:
                db.rollback()
                flash("This election just closed. Your vote was not recorded.", "error")
                return redirect(url_for("vote_list"))
            db.execute("INSERT INTO voters (election_id, user_id, voted_at) VALUES (?, ?, ?)",
                       (election_id, g.user["id"], now()))
            db.execute("INSERT INTO ballots (id, election_id, candidate_id, cast_at) "
                       "VALUES (?, ?, ?, ?)", (receipt, election_id, candidate_id, now()))
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            flash("You have already voted in this election.", "error")
            return redirect(url_for("vote_list"))
        flash(f"Your vote was recorded. Receipt (keep it, it is shown once): {receipt}",
              "success")
        return redirect(url_for("vote_list"))
    return render_template("ballot.html", election=election, candidates=candidates)


@app.route("/results")
def result():
    elections = get_db().execute(
        "SELECT id, title, description, closed_at FROM elections "
        "WHERE results_published = 1 ORDER BY closed_at DESC").fetchall()
    return render_template("result.html", elections=elections)


@app.route("/results/<election_id>")
def result_detail(election_id):
    election = get_election_or_404(election_id)
    if not election["results_published"]:
        abort(404)
    rows, total, turnout, winners = tally(election_id)
    return render_template("result_detail.html", election=election, rows=rows,
                           total=total, turnout=turnout, winners=winners)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db = get_db()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "email":
            email = request.form.get("email", "").strip().lower()
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 120:
                flash("Enter a valid email address.", "error")
            else:
                try:
                    db.execute("UPDATE users SET email = ? WHERE id = ?", (email, g.user["id"]))
                    db.commit()
                    flash("Email updated.", "success")
                except sqlite3.IntegrityError:
                    flash("That email is already in use.", "error")
        elif action == "password":
            current = request.form.get("current_password", "")
            new = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            row = db.execute("SELECT password_hash FROM users WHERE id = ?",
                             (g.user["id"],)).fetchone()
            pw_error = validate_password(new)
            if not check_password_hash(row["password_hash"], current):
                flash("Current password is incorrect.", "error")
            elif pw_error:
                flash(pw_error, "error")
            elif new != confirm:
                flash("New passwords do not match.", "error")
            else:
                db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                           (generate_password_hash(new), g.user["id"]))
                db.commit()
                keep = session.get("csrf_token")
                session.clear()
                session.permanent = True
                session["user_id"] = g.user["id"]
                session["csrf_token"] = keep
                flash("Password changed.", "success")
        return redirect(url_for("profile"))
    history = db.execute(
        """SELECT e.id, e.title, v.voted_at FROM voters v
           JOIN elections e ON e.id = v.election_id
           WHERE v.user_id = ? ORDER BY v.voted_at DESC""", (g.user["id"],)).fetchall()
    return render_template("profile.html", history=history)

@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    count = lambda sql: db.execute(sql).fetchone()[0]
    stats = {
        "users": count("SELECT COUNT(*) FROM users WHERE role='user'"),
        "draft": count("SELECT COUNT(*) FROM elections WHERE status='draft'"),
        "open": count("SELECT COUNT(*) FROM elections WHERE status='open'"),
        "closed": count("SELECT COUNT(*) FROM elections WHERE status='closed'"),
        "ballots": count("SELECT COUNT(*) FROM ballots"),
        "awaiting": count("SELECT COUNT(*) FROM elections "
                          "WHERE status='closed' AND results_published=0"),
    }
    recent = db.execute(
        """SELECT e.id, e.title, e.status, e.results_published,
                  (SELECT COUNT(*) FROM candidates c WHERE c.election_id = e.id) AS n_candidates,
                  (SELECT COUNT(*) FROM ballots b WHERE b.election_id = e.id) AS n_votes
           FROM elections e ORDER BY e.created_at DESC LIMIT 6""").fetchall()
    return render_template("admin/dashboard.html", stats=stats, recent=recent)


@app.route("/admin/elections", methods=["GET", "POST"])
@admin_required
def manage_elections():
    db = get_db()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        if not (3 <= len(title) <= 120) or len(description) > 1000:
            flash("Title must be 3-120 characters (description max 1000).", "error")
        else:
            db.execute(
                "INSERT INTO elections (id, title, description, created_at) VALUES (?, ?, ?, ?)",
                (new_id(), title, description, now()))
            db.commit()
            flash("Election created as a draft. Add candidates, then open it.", "success")
        return redirect(url_for("manage_elections"))
    elections = db.execute(
        """SELECT e.*,
                  (SELECT COUNT(*) FROM candidates c WHERE c.election_id = e.id) AS n_candidates,
                  (SELECT COUNT(*) FROM ballots b WHERE b.election_id = e.id) AS n_votes
           FROM elections e ORDER BY e.created_at DESC""").fetchall()
    return render_template("admin/manage_elections.html", elections=elections)


@app.route("/admin/elections/<election_id>/edit", methods=["POST"])
@admin_required
def edit_election(election_id):
    election = get_election_or_404(election_id)
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    if election["status"] != "draft":
        flash("Only draft elections can be edited.", "error")
    elif not (3 <= len(title) <= 120) or len(description) > 1000:
        flash("Title must be 3-120 characters (description max 1000).", "error")
    else:
        db = get_db()
        db.execute("UPDATE elections SET title = ?, description = ? WHERE id = ?",
                   (title, description, election_id))
        db.commit()
        flash("Election updated.", "success")
    return redirect(url_for("manage_elections"))


@app.route("/admin/elections/<election_id>/status", methods=["POST"])
@admin_required
def set_election_status(election_id):
    db = get_db()
    election = get_election_or_404(election_id)
    action = request.form.get("action")
    if action == "open" and election["status"] == "draft":
        n = db.execute("SELECT COUNT(*) FROM candidates WHERE election_id = ?",
                       (election_id,)).fetchone()[0]
        if n < 2:
            flash("Add at least two candidates before opening an election.", "error")
        else:
            db.execute("UPDATE elections SET status='open', opened_at=? WHERE id=?",
                       (now(), election_id))
            db.commit()
            flash("Election is now open for voting.", "success")
    elif action == "close" and election["status"] == "open":
        db.execute("UPDATE elections SET status='closed', closed_at=? WHERE id=?",
                   (now(), election_id))
        db.commit()
        flash("Election closed. You can now publish its results.", "success")
    else:
        flash("That change is not allowed for the election's current state.", "error")
    return redirect(url_for("manage_elections"))


@app.route("/admin/elections/<election_id>/delete", methods=["POST"])
@admin_required
def delete_election(election_id):
    election = get_election_or_404(election_id)
    if election["status"] == "open":
        flash("Close the election before deleting it.", "error")
    else:
        db = get_db()
        db.execute("DELETE FROM elections WHERE id = ?", (election_id,))
        db.commit()
        flash("Election deleted.", "success")
    return redirect(url_for("manage_elections"))


@app.route("/admin/candidates", methods=["GET", "POST"])
@admin_required
def manage_candidates():
    db = get_db()
    if request.method == "POST":
        election_id = request.form.get("election_id", "")
        election = get_election_or_404(election_id)
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        if election["status"] != "draft":
            flash("Candidates can only be added while the election is a draft.", "error")
        elif not (2 <= len(name) <= 80) or len(description) > 500:
            flash("Candidate name must be 2-80 characters (description max 500).", "error")
        elif db.execute("SELECT 1 FROM candidates WHERE election_id=? AND name=? COLLATE NOCASE",
                        (election_id, name)).fetchone():
            flash("A candidate with that name already exists in this election.", "error")
        else:
            db.execute(
                "INSERT INTO candidates (id, election_id, name, description, created_at) "
                "VALUES (?, ?, ?, ?, ?)", (new_id(), election_id, name, description, now()))
            db.commit()
            flash("Candidate added.", "success")
        return redirect(url_for("manage_candidates", election=election_id))

    elections = db.execute("SELECT id, title, status FROM elections "
                           "ORDER BY created_at DESC").fetchall()
    selected = None
    candidates = []
    chosen = request.args.get("election") or (elections[0]["id"] if elections else None)
    if chosen:
        selected = get_election_or_404(chosen)
        candidates = db.execute(
            "SELECT * FROM candidates WHERE election_id = ? ORDER BY name COLLATE NOCASE",
            (chosen,)).fetchall()
    return render_template("admin/manage_candidates.html", elections=elections,
                           selected=selected, candidates=candidates)


@app.route("/admin/candidates/<candidate_id>/delete", methods=["POST"])
@admin_required
def delete_candidate(candidate_id):
    db = get_db()
    cand = db.execute(
        "SELECT c.id, c.election_id, e.status FROM candidates c "
        "JOIN elections e ON e.id = c.election_id WHERE c.id = ?", (candidate_id,)).fetchone()
    if cand is None:
        abort(404)
    if cand["status"] != "draft":
        flash("Candidates can only be removed while the election is a draft.", "error")
    else:
        db.execute("DELETE FROM candidates WHERE id = ?", (candidate_id,))
        db.commit()
        flash("Candidate removed.", "success")
    return redirect(url_for("manage_candidates", election=cand["election_id"]))


@app.route("/admin/results")
@admin_required
def publish_result():
    db = get_db()
    elections = db.execute(
        "SELECT * FROM elections WHERE status IN ('open', 'closed') "
        "ORDER BY created_at DESC").fetchall()
    data = []
    for e in elections:
        rows, total, turnout, winners = tally(e["id"])
        data.append({"election": e, "rows": rows, "total": total,
                     "turnout": turnout, "winners": winners})
    return render_template("admin/publish_result.html", data=data)


@app.route("/admin/results/<election_id>", methods=["POST"])
@admin_required
def set_result_visibility(election_id):
    election = get_election_or_404(election_id)
    action = request.form.get("action")
    db = get_db()
    if action == "publish":
        if election["status"] != "closed":
            flash("Close the election before publishing its results.", "error")
        else:
            db.execute("UPDATE elections SET results_published = 1 WHERE id = ?", (election_id,))
            db.commit()
            flash("Results published. Everyone can see them now.", "success")
    elif action == "unpublish":
        db.execute("UPDATE elections SET results_published = 0 WHERE id = ?", (election_id,))
        db.commit()
        flash("Results hidden from the public.", "success")
    return redirect(url_for("publish_result"))

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def http_error(err):
    return render_template("error.html", code=err.code, message=err.description), err.code


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
