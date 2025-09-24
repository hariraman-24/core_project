from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from datetime import datetime, timedelta, timezone
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "replace_with_secure_key")

# === DATABASE CONFIG ===
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:0987654321@localhost/dfa_security"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# === MODELS ===
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String(45), nullable=False)
    result = db.Column(db.String(32))   # "SUCCESS", "FAILED", "BLOCKED_TRY", "BLOCKED"
    state = db.Column(db.String(32))    # "S0","S1",...,"BLOCKED"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class BlockedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String(45), nullable=False)
    blocked_until = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# === CONFIG: DFA PARAMETERS ===
THRESHOLD = 3            # fails needed to trigger block
WINDOW_SECONDS = 60      # sliding window to count failures
BLOCK_SECONDS = 300      # block duration (5 minutes)

# === HELPERS ===
def init_db_and_demo_users():
    db.create_all()
    if not User.query.first():
        demo = [("admin", "1234"), ("test", "pass")]
        for u, p in demo:
            if not User.query.filter_by(username=u).first():
                db.session.add(User(username=u, password=p))
        db.session.commit()

def client_ip_from_request(req):
    return req.headers.get("X-Forwarded-For", req.remote_addr)

def log_attempt(ip, result, state):
    a = LoginAttempt(ip=ip, result=result, state=state)
    db.session.add(a)
    db.session.commit()

def add_block(ip, duration_seconds=BLOCK_SECONDS, reason="threshold_exceeded"):
    until = datetime.utcnow() + timedelta(seconds=duration_seconds)
    rec = BlockedUser(ip=ip, blocked_until=until, reason=reason)
    db.session.add(rec)
    db.session.commit()
    return rec

def is_blocked(ip):
    now = datetime.utcnow()
    rec = BlockedUser.query.filter(BlockedUser.blocked_until > now, BlockedUser.ip == ip).first()
    return rec

def count_recent_failures_for_ip(ip):
    cutoff = datetime.utcnow() - timedelta(seconds=WINDOW_SECONDS)
    return LoginAttempt.query.filter(
        LoginAttempt.ip == ip,
        LoginAttempt.result == "FAILED",
        LoginAttempt.created_at >= cutoff
    ).count()

# === ROUTES ===
@app.route("/", methods=["GET"])
def index():
    return render_template("login.html", threshold=THRESHOLD, window_seconds=WINDOW_SECONDS, block_seconds=BLOCK_SECONDS)

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    ip = client_ip_from_request(request)

    # 1) Check active IP block
    rec = is_blocked(ip)
    if rec:
        remaining = int((rec.blocked_until - datetime.utcnow()).total_seconds())
        log_attempt(ip, "BLOCKED_TRY", "BLOCKED")
        flash(f"🚫 Blocked: Try again in {remaining}s", "error")
        return redirect(url_for("index"))

    # 2) Validate user
    user = User.query.filter_by(username=username).first()
    ok = (user is not None and user.password == password)

    if ok:
        log_attempt(ip, "SUCCESS", "S0")
        flash("✅ Login successful!", "success")
        return redirect(url_for("index"))
    else:
        # Count prior failures to determine the current DFA state
        ip_failures = count_recent_failures_for_ip(ip)
        
        # The new state is S(n+1)
        current_state = f"S{ip_failures + 1}"
        log_attempt(ip, "FAILED", current_state)

        # Check if the new failure count meets the threshold
        total_failures = ip_failures + 1
        if total_failures >= THRESHOLD:
            add_block(ip, BLOCK_SECONDS, "ip_threshold")
            log_attempt(ip, "BLOCKED", "BLOCKED")  # Log a final event indicating the block
            flash(f"🚨 Brute-force detected. IP blocked for {BLOCK_SECONDS}s.", "error")
        else:
            flash(f"❌ Wrong credentials. Failures for this IP: {total_failures}/{THRESHOLD}", "error")
        
        return redirect(url_for("index"))

@app.route("/logs")
def logs():
    recent = LoginAttempt.query.order_by(LoginAttempt.created_at.desc()).limit(300).all()
    return render_template("logs.html", attempts=recent)

@app.route("/blocked")
def blocked():
    now = datetime.utcnow()
    active = BlockedUser.query.filter(BlockedUser.blocked_until > now).order_by(BlockedUser.blocked_until.desc()).all()
    return render_template("blocked.html", blocks=active)

@app.route("/admin/unblock/<int:block_id>", methods=["POST"])
def admin_unblock(block_id):
    rec = BlockedUser.query.get(block_id)
    if rec:
        db.session.delete(rec)
        db.session.commit()
        flash("✅ Unblocked successfully.", "success")
    else:
        flash("❌ Block record not found.", "error")
    return redirect(url_for("blocked"))

# === STARTUP ===
if __name__ == "__main__":
    with app.app_context():
        init_db_and_demo_users()
    app.run(debug=True)
