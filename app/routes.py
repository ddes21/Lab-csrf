from flask import Blueprint, request, session, redirect, url_for, render_template, abort, make_response
from secrets import token_hex
from urllib.parse import urlparse, urlencode

bp = Blueprint("main", __name__)

# ------------------------------ Data -----------------------------------------
def mint_token(prefix: str) -> str:
    return f"{prefix}-{token_hex(8)}"

# Only Bob is known; Admin's password is unknown
users = {
    "admin": {"password": "ThisIsSuperSecret!", "login_csrf": None},
    "bob":   {"password": "bob",                "login_csrf": None},
}

# Pending continuation flows created after a successful password check
# flow_id -> {"username": <original user>, "next": <intended next>}
pending_flows = {}

FLAG = "FLAG{admin-via-redirect-manipulation-and-header-csrf}"

# ---------------------------- Helpers ----------------------------------------
def safe_next(target: str, default="/dashboard") -> str:
    """Allow only internal absolute paths; block external/relative tricks."""
    if not target:
        return default
    p = urlparse(target)
    if p.scheme or p.netloc:
        return default
    if not target.startswith("/"):
        return default
    return target

def find_owner_of_login_csrf(token: str | None):
    if not token:
        return None
    for uname, rec in users.items():
        if rec.get("login_csrf") == token:
            return uname
    return None

def invalidate_login_csrf(token: str | None):
    owner = find_owner_of_login_csrf(token)
    if owner:
        users[owner]["login_csrf"] = None

# ------------------------------ Routes ---------------------------------------
@bp.route("/")
def root():
    return redirect(url_for("main.dashboard") if session.get("user") else url_for("main.login"))

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        posted_username = (request.form.get("username") or "").strip().lower()
        posted_password = request.form.get("password") or ""
        next_url = safe_next(request.form.get("next", "/dashboard"))

        # Only real, password-checked login; students know bob/bob
        if posted_username in users and users[posted_username]["password"] == posted_password:
            # Mint SINGLE-USE token for that account
            token = mint_token(posted_username.upper())
            users[posted_username]["login_csrf"] = token

            # Create a pending continuation flow so normal users also succeed
            flow_id = token_hex(8)
            pending_flows[flow_id] = {"username": posted_username, "next": next_url}

            # Server-chosen continuation target (students will tamper this later in Burp)
            cont_qs = urlencode({"flow": flow_id, "username": posted_username, "next": next_url})
            cont_url = url_for("main.continue_login", _external=False) + f"?{cont_qs}"

            # Return an HTML page that IMMEDIATELY requests /continue WITH the header
            # => You will see the header in the /continue REQUEST automatically.
            return render_template("auto_continue.html", continue_url=cont_url, login_token=token)


        return render_template("login.html", error="Invalid credentials.")

    return render_template("login.html", error=None)

@bp.route("/continue", methods=["GET"])
def continue_login():
    flow_id = request.args.get("flow", "")
    pf = pending_flows.pop(flow_id, None)  # one-shot continuation
    if not pf:
        return redirect(url_for("main.login"))

    supplied_csrf = request.headers.get("X-Login-CSRF", "")
    target_username = (request.args.get("username") or "").strip().lower()
    next_url = safe_next(request.args.get("next", pf["next"]))

    owner = find_owner_of_login_csrf(supplied_csrf)

    if owner:
        # VULNERABLE FINALIZE:
        # - accepts ANY user's single-use token (not bound to flow/user)
        # - consumes it (single-use)
        # - trusts the tamperable query param 'username'
        invalidate_login_csrf(supplied_csrf)
        session["user"] = target_username   # <-- bug
        return redirect(next_url)

    # If no/invalid header, finalize as the original user (normal flow)
    users[pf["username"]]["login_csrf"] = None
    session["user"] = pf["username"]
    return redirect(pf["next"])

@bp.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("main.login"))
    return render_template("dashboard.html", user=session["user"])

@bp.route("/admin")
def admin():
    if session.get("user") != "admin":
        abort(403)
    return render_template("admin.html", flag=FLAG)

@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login"))
