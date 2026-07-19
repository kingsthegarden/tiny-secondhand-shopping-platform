"""Sign-up / login / logout."""
import secrets
from datetime import timedelta

from flask import (Blueprint, current_app, flash, g, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from market.forms import LoginForm, RegisterForm
from market.models import User, audit, db, utcnow
from market.utils import rate_limited

bp = Blueprint("auth", __name__)

# Precomputed hash of a value nobody will ever type, used to run
# check_password_hash on a nonexistent user too. Without this, a login for
# an unknown username returns almost instantly (no hash to compute) while
# a login for a real username always pays the scrypt cost, letting an
# attacker enumerate valid usernames purely from response timing even
# though the error message itself is identical either way.
_DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_hex(32))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("main.index"))
    form = RegisterForm()
    if request.method == "POST" and rate_limited(
            f"register:{request.remote_addr}", limit=5, window_seconds=3600):
        flash("회원가입 시도가 너무 잦습니다. 잠시 후 다시 시도해주세요.", "danger")
        return render_template("auth/register.html", form=form)
    if form.validate_on_submit():
        username = form.username.data
        exists = db.session.execute(
            db.select(User).filter_by(username=username)).scalar_one_or_none()
        if exists:
            flash("이미 사용 중인 아이디입니다.", "danger")
        else:
            user = User(
                username=username,
                password_hash=generate_password_hash(form.password.data),
                balance=current_app.config["STARTING_BALANCE"],
            )
            db.session.add(user)
            audit("register", f"username={username}")
            db.session.commit()
            flash("회원가입이 완료되었습니다. 로그인해주세요.", "success")
            return redirect(url_for("auth.login"))
    return render_template("auth/register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("main.index"))
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data

        # Per-IP rate limit (brute force / credential stuffing defense).
        if rate_limited(f"login:{request.remote_addr}", limit=10, window_seconds=60):
            flash("로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.", "danger")
            return render_template("auth/login.html", form=form)

        user = db.session.execute(
            db.select(User).filter_by(username=username)).scalar_one_or_none()

        # Per-account lockout after repeated failures.
        if user and user.locked_until and user.locked_until > utcnow():
            flash("로그인 실패가 반복되어 계정이 일시적으로 잠겼습니다. 잠시 후 다시 시도해주세요.", "danger")
            return render_template("auth/login.html", form=form)

        # Always run a hash comparison, even for a nonexistent user, against
        # a fixed dummy hash — keeps response time constant regardless of
        # whether the username exists (see _DUMMY_PASSWORD_HASH above).
        password_ok = check_password_hash(
            user.password_hash if user else _DUMMY_PASSWORD_HASH,
            form.password.data)
        if user and password_ok:
            if user.status == User.STATUS_DORMANT:
                flash("휴면 계정입니다. 관리자에게 문의해주세요.", "warning")
                return render_template("auth/login.html", form=form)
            if user.status == User.STATUS_BANNED:
                flash("이용이 제한된 계정입니다. 관리자에게 문의해주세요.", "danger")
                return render_template("auth/login.html", form=form)

            user.failed_logins = 0
            user.locked_until = None
            audit("login_success", f"username={username}", actor_id=user.id)
            db.session.commit()

            # Session fixation defense: start from a fresh session.
            session.clear()
            session["user_id"] = user.id
            session.permanent = True

            next_url = request.args.get("next", "")
            # Open-redirect defense: only allow same-site relative paths.
            if not next_url.startswith("/") or next_url.startswith("//"):
                next_url = url_for("main.index")
            return redirect(next_url)

        # Failure: identical message whether the id or password was wrong
        # (prevents username enumeration).
        if user:
            user.failed_logins += 1
            if user.failed_logins >= current_app.config["LOGIN_MAX_FAILURES"]:
                user.locked_until = utcnow() + timedelta(
                    seconds=current_app.config["LOGIN_LOCKOUT_SECONDS"])
                user.failed_logins = 0
                audit("login_lockout", f"username={username}")
        audit("login_failure", f"username={username}")
        db.session.commit()
        flash("아이디 또는 비밀번호가 올바르지 않습니다.", "danger")
    return render_template("auth/login.html", form=form)


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("로그아웃되었습니다.", "success")
    return redirect(url_for("main.index"))
