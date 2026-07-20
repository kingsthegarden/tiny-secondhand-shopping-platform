"""Application factory."""
from flask import Flask, flash, g, redirect, render_template, session, url_for
from flask_socketio import SocketIO
from flask_wtf import CSRFProtect

from config import Config
from market.models import User, db

csrf = CSRFProtect()
socketio = SocketIO()


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    db.init_app(app)
    csrf.init_app(app)
    # Async mode 'threading' works with the standard dev server.
    # cors_allowed_origins is left at its default: same-origin only
    # (blocks cross-site WebSocket hijacking).
    socketio.init_app(app, async_mode="threading")

    # --- Blueprints ---
    from market.routes.auth import bp as auth_bp
    from market.routes.main import bp as main_bp
    from market.routes.products import bp as products_bp
    from market.routes.users import bp as users_bp
    from market.routes.chat import bp as chat_bp
    from market.routes.wallet import bp as wallet_bp
    from market.routes.reports import bp as reports_bp
    from market.routes.admin import bp as admin_bp
    for bp in (auth_bp, main_bp, products_bp, users_bp, chat_bp,
               wallet_bp, reports_bp, admin_bp):
        app.register_blueprint(bp)

    # --- SocketIO event handlers ---
    from market import sockets  # noqa: F401  (registers handlers on import)

    # --- Load current user for each request ---
    @app.before_request
    def load_current_user():
        g.user = None
        user_id = session.get("user_id")
        if user_id is not None:
            user = db.session.get(User, user_id)
            # If the account went dormant/banned mid-session, kill the session.
            if user is not None and user.is_active_user:
                g.user = user
            elif user is not None:
                session.clear()

    @app.context_processor
    def inject_user():
        return {"current_user": g.get("user")}

    # --- Security headers on every response ---
    @app.after_request
    def set_security_headers(resp):
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "script-src 'self'; style-src 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        return resp

    # --- Error handlers: never leak stack traces / internals to users ---
    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", code=403,
                               message="접근 권한이 없습니다."), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404,
                               message="페이지를 찾을 수 없습니다."), 404

    @app.errorhandler(413)
    def too_large(e):
        return render_template("error.html", code=413,
                               message="업로드 용량 제한(2MB)을 초과했습니다."), 413

    @app.errorhandler(500)
    def internal_error(e):
        db.session.rollback()
        return render_template("error.html", code=500,
                               message="서버 오류가 발생했습니다."), 500

    from flask_wtf.csrf import CSRFError

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        flash("요청 검증에 실패했습니다. 다시 시도해주세요.", "danger")
        return redirect(url_for("main.index"))

    with app.app_context():
        db.create_all()

    # --- CLI: create an admin account ---
    import click

    @app.cli.command("create-admin")
    @click.argument("username")
    @click.password_option()
    def create_admin(username, password):
        """Create a new admin account, or promote an existing account to admin."""
        import re
        from werkzeug.security import generate_password_hash
        from market.forms import USERNAME_RE
        if not re.match(USERNAME_RE, username):
            raise click.ClickException("잘못된 아이디 형식입니다 (영문/숫자/_ 3~20자).")
        if len(password) < 8:
            raise click.ClickException("비밀번호는 8자 이상이어야 합니다.")
        user = db.session.execute(
            db.select(User).filter_by(username=username)).scalar_one_or_none()
        if user is None:
            user = User(username=username,
                        password_hash=generate_password_hash(password),
                        role="admin",
                        balance=app.config["STARTING_BALANCE"])
            db.session.add(user)
            db.session.commit()
            click.echo(f"관리자 계정을 새로 생성했습니다: {username}")
        else:
            # Previously this branch only flipped `role`, silently keeping
            # whatever password the account already had -- running this
            # command with a *new* password against an existing username
            # looked like it worked (same success message either way) but
            # the old password stayed in effect, so a login with the
            # password just typed would always fail. Set the password (and
            # clear any failed-login lockout) so the command does what its
            # own output claims.
            user.role = "admin"
            user.password_hash = generate_password_hash(password)
            user.failed_logins = 0
            user.locked_until = None
            db.session.commit()
            click.echo(f"기존 계정을 관리자로 승격하고 비밀번호를 갱신했습니다: {username}")

    # --- CLI: seed a few demo products (optional, dev/demo only) ---
    @app.cli.command("seed-demo")
    def seed_demo():
        """Create a demo seller + sample products so the listing isn't empty.

        Safe to run repeatedly (skips if already seeded). Not run
        automatically on startup — invoke it explicitly when you want demo
        data, e.g. right after a fresh clone.
        """
        import secrets as _secrets

        from werkzeug.security import generate_password_hash
        from market.models import Product

        seller = db.session.execute(
            db.select(User).filter_by(username="demo_seller")).scalar_one_or_none()
        if seller is None:
            # Random password: this account only exists to own demo listings,
            # nobody is meant to log into it, so there is no fixed/predictable
            # credential sitting in the source code.
            seller = User(
                username="demo_seller",
                password_hash=generate_password_hash(_secrets.token_urlsafe(24)),
                bio="데모용 판매자 계정입니다.",
                balance=app.config["STARTING_BALANCE"],
            )
            db.session.add(seller)
            db.session.flush()

        if db.session.execute(
                db.select(Product).filter_by(seller_id=seller.id)).first():
            click.echo("이미 데모 상품이 있습니다. 건너뜁니다.")
            return

        demo_products = [
            ("아이폰 13 미니 128GB", "배터리 성능 92%, 생활기스 약간 있음. 박스/충전기 포함.", 450_000),
            ("무선 이어폰 (버즈 프로)", "구매 6개월, 케이스 포함, 정상 작동합니다.", 60_000),
            ("자바의 정석 3판 (전공서적)", "필기 거의 없음, 밑줄 몇 군데. 학기 끝나서 판매.", 12_000),
            ("접이식 자전거 20인치", "출퇴근용으로 쓰던 자전거, 타이어 최근 교체.", 90_000),
            ("네스프레소 캡슐 커피머신", "이사 때문에 판매, 세척 완료 상태.", 55_000),
            ("게이밍 모니터 27인치 165hz", "번인 없음, QHD 해상도, 박스 있음.", 180_000),
        ]
        for title, description, price in demo_products:
            db.session.add(Product(title=title, description=description,
                                   price=price, seller_id=seller.id))
        db.session.commit()
        click.echo(f"데모 상품 {len(demo_products)}개를 등록했습니다 (판매자: demo_seller).")

    return app
