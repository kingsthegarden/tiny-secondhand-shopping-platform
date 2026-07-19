"""Security-focused tests: each test maps to a checklist item."""
from market.models import Product, Report, User, db
from tests.conftest import get_csrf, login


# ---------------------------------------------------------------- auth ----

def test_password_stored_hashed(app):
    """비밀번호 평문 저장 금지."""
    user = db.session.execute(db.select(User).filter_by(username="alice")).scalar_one()
    assert "TestPass921" not in user.password_hash
    assert user.password_hash.startswith(("scrypt:", "pbkdf2:"))


def test_register_rejects_weak_password(client):
    token = get_csrf(client, "/register")
    resp = client.post("/register", data={
        "csrf_token": token, "username": "newbie",
        "password": "short", "password2": "short"})
    assert "8~64자".encode() in resp.data
    assert db.session.execute(
        db.select(User).filter_by(username="newbie")).scalar_one_or_none() is None


def test_register_rejects_bad_username(client):
    token = get_csrf(client, "/register")
    resp = client.post("/register", data={
        "csrf_token": token, "username": "<script>alert(1)</script>",
        "password": "TestPass921", "password2": "TestPass921"})
    assert "아이디는".encode() in resp.data


def test_login_wrong_password_generic_error(client):
    token = get_csrf(client, "/login")
    resp = client.post("/login", data={
        "csrf_token": token, "username": "alice", "password": "WrongPw123"})
    # same message for wrong id / wrong pw (no user enumeration)
    assert "아이디 또는 비밀번호가 올바르지 않습니다".encode() in resp.data


def test_login_nonexistent_user_same_message(client):
    """존재하지 않는 아이디로 로그인해도 동일한 실패 메시지(응답 자체는 즉시 200)."""
    token = get_csrf(client, "/login")
    resp = client.post("/login", data={
        "csrf_token": token, "username": "no_such_user", "password": "WrongPw123"})
    assert resp.status_code == 200
    assert "아이디 또는 비밀번호가 올바르지 않습니다".encode() in resp.data


def test_register_rejects_common_password(client):
    token = get_csrf(client, "/register")
    resp = client.post("/register", data={
        "csrf_token": token, "username": "newbie2",
        "password": "password123", "password2": "password123"})
    assert "흔하게 쓰이는".encode() in resp.data
    assert db.session.execute(
        db.select(User).filter_by(username="newbie2")).scalar_one_or_none() is None


def test_register_rate_limited(app, client):
    for i in range(6):
        token = get_csrf(client, "/register")
        resp = client.post("/register", data={
            "csrf_token": token, "username": f"ratelimit{i}",
            "password": "TestPass921", "password2": "TestPass921"},
            follow_redirects=True)
    assert "너무 잦습니다".encode() in resp.data


def test_account_lockout_after_failures(app, client):
    for _ in range(5):
        token = get_csrf(client, "/login")
        client.post("/login", data={
            "csrf_token": token, "username": "alice", "password": "WrongPw123"})
    user = db.session.execute(db.select(User).filter_by(username="alice")).scalar_one()
    assert user.locked_until is not None
    # correct password is also rejected while locked
    resp = login(client)
    assert "잠겼습니다".encode() in resp.data


def test_dormant_user_cannot_login(app, client):
    user = db.session.execute(db.select(User).filter_by(username="alice")).scalar_one()
    user.status = User.STATUS_DORMANT
    db.session.commit()
    resp = login(client)
    assert "휴면 계정".encode() in resp.data


# ---------------------------------------------------------------- csrf ----

def test_post_without_csrf_token_rejected(client):
    login(client)
    resp = client.post("/users/me/bio", data={"bio": "no token"},
                       follow_redirects=True)
    assert "요청 검증에 실패".encode() in resp.data
    user = db.session.execute(db.select(User).filter_by(username="alice")).scalar_one()
    assert user.bio != "no token"


# ------------------------------------------------------- access control ----

def test_anonymous_redirected_to_login(client):
    for url in ["/products/new", "/users/me", "/wallet/", "/chat/", "/products/mine"]:
        resp = client.get(url)
        assert resp.status_code == 302 and "/login" in resp.headers["Location"], url


def test_admin_pages_forbidden_for_normal_user(client):
    login(client)
    for url in ["/admin/", "/admin/users", "/admin/reports", "/admin/logs"]:
        assert client.get(url).status_code == 403, url


def test_idor_cannot_edit_others_product(app, client):
    bob = db.session.execute(db.select(User).filter_by(username="bob")).scalar_one()
    product = Product(title="bob's item", description="d", price=1000,
                      seller_id=bob.id)
    db.session.add(product)
    db.session.commit()
    login(client)  # alice
    assert client.get(f"/products/{product.id}/edit").status_code == 403
    token = get_csrf(client, "/products/new")
    resp = client.post(f"/products/{product.id}/delete",
                       data={"csrf_token": token})
    assert resp.status_code == 403


def test_admin_cannot_change_own_role_or_status(app, client):
    """자기 자신의 role/status는 관리자 화면에서 바꿀 수 없음(자기 잠금 방지)."""
    admin = db.session.execute(db.select(User).filter_by(username="admin1")).scalar_one()
    login(client, username="admin1")
    token = get_csrf(client, "/admin/users")
    resp = client.post(f"/admin/users/{admin.id}/update", data={
        "csrf_token": token, "status": "dormant", "role": "user"},
        follow_redirects=True)
    assert "자기 자신의 계정은".encode() in resp.data
    db.session.expire_all()
    assert admin.role == "admin" and admin.status == User.STATUS_ACTIVE


# ------------------------------------------------------------ injection ----

def test_search_sql_injection_is_inert(client):
    resp = client.get("/products?q=%27%20OR%201%3D1--")   # ' OR 1=1--
    assert resp.status_code == 200
    assert "검색 결과가 없습니다".encode() in resp.data


def test_search_like_wildcards_literal(app, client):
    alice = db.session.execute(db.select(User).filter_by(username="alice")).scalar_one()
    db.session.add(Product(title="normal item", description="d", price=1,
                           seller_id=alice.id))
    db.session.commit()
    # '%' must not match everything
    resp = client.get("/products?q=%25")
    assert "검색 결과가 없습니다".encode() in resp.data


def test_xss_in_product_description_escaped(app, client):
    login(client)
    token = get_csrf(client, "/products/new")
    payload = "<script>alert('xss')</script>"
    client.post("/products/new", data={
        "csrf_token": token, "title": "xss test", "description": payload,
        "price": "1000"}, follow_redirects=True)
    product = db.session.execute(
        db.select(Product).filter_by(title="xss test")).scalar_one()
    resp = client.get(f"/products/{product.id}")
    assert b"<script>alert" not in resp.data
    assert b"&lt;script&gt;" in resp.data


# ------------------------------------------------------------- transfers ----

def test_transfer_insufficient_balance(client):
    login(client)
    token = get_csrf(client, "/wallet/")
    resp = client.post("/wallet/", data={
        "csrf_token": token, "receiver": "bob", "amount": "99999999",
        "memo": ""}, follow_redirects=True)
    assert "금액은".encode() in resp.data or "잔액이 부족".encode() in resp.data
    bob = db.session.execute(db.select(User).filter_by(username="bob")).scalar_one()
    assert bob.balance == 100_000


def test_transfer_negative_amount_rejected(client):
    login(client)
    token = get_csrf(client, "/wallet/")
    client.post("/wallet/", data={
        "csrf_token": token, "receiver": "bob", "amount": "-5000", "memo": ""},
        follow_redirects=True)
    alice = db.session.execute(db.select(User).filter_by(username="alice")).scalar_one()
    bob = db.session.execute(db.select(User).filter_by(username="bob")).scalar_one()
    assert alice.balance == 100_000 and bob.balance == 100_000


def test_transfer_to_self_rejected(client):
    login(client)
    token = get_csrf(client, "/wallet/")
    resp = client.post("/wallet/", data={
        "csrf_token": token, "receiver": "alice", "amount": "1000", "memo": ""},
        follow_redirects=True)
    assert "자기 자신에게는 송금할 수 없습니다".encode() in resp.data


def test_transfer_success_moves_money(client):
    login(client)
    token = get_csrf(client, "/wallet/")
    client.post("/wallet/", data={
        "csrf_token": token, "receiver": "bob", "amount": "30000",
        "memo": "test"}, follow_redirects=True)
    alice = db.session.execute(db.select(User).filter_by(username="alice")).scalar_one()
    bob = db.session.execute(db.select(User).filter_by(username="bob")).scalar_one()
    assert alice.balance == 70_000 and bob.balance == 130_000


# --------------------------------------------------------------- reports ----

def test_duplicate_report_rejected(app, client):
    bob = db.session.execute(db.select(User).filter_by(username="bob")).scalar_one()
    login(client)
    url = f"/report/user/{bob.id}"
    token = get_csrf(client, url)
    client.post(url, data={"csrf_token": token, "reason": "불량 사용자입니다."},
                follow_redirects=True)
    token = get_csrf(client, "/products/new")
    resp = client.post(url, data={"csrf_token": token, "reason": "다시 신고합니다."},
                       follow_redirects=True)
    assert "이미 신고한 대상입니다".encode() in resp.data
    count = db.session.scalar(db.select(db.func.count()).select_from(Report))
    assert count == 1


def test_product_blocked_after_threshold_reports(app, client):
    """서로 다른 사용자 3명이 신고하면 상품 자동 차단."""
    from werkzeug.security import generate_password_hash
    alice = db.session.execute(db.select(User).filter_by(username="alice")).scalar_one()
    product = Product(title="bad item", description="d", price=1,
                      seller_id=alice.id)
    db.session.add(product)
    for i in range(3):
        db.session.add(User(username=f"reporter{i}",
                            password_hash=generate_password_hash("TestPass921"),
                            balance=0))
    db.session.commit()

    for i in range(3):
        c = app.test_client()
        login(c, username=f"reporter{i}")
        url = f"/report/product/{product.id}"
        token = get_csrf(c, url)
        c.post(url, data={"csrf_token": token, "reason": "불량 상품입니다."},
               follow_redirects=True)

    db.session.expire_all()
    assert product.status == Product.STATUS_BLOCKED
    # blocked product hidden from list and detail
    anon = app.test_client()
    assert "bad item".encode() not in anon.get("/products").data
    assert anon.get(f"/products/{product.id}").status_code == 404


# ---------------------------------------------------------------- misc ----

def test_security_headers_present(client):
    resp = client.get("/")
    assert "Content-Security-Policy" in resp.headers
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_session_cookie_httponly(client):
    login(client)
    cookies = client.get_cookie("session")
    assert cookies is not None and cookies.http_only


def test_fake_image_upload_rejected(client):
    """확장자만 png인 스크립트 파일 업로드 차단(매직바이트 검사)."""
    import io
    login(client)
    token = get_csrf(client, "/products/new")
    resp = client.post("/products/new", data={
        "csrf_token": token, "title": "fake image", "description": "d",
        "price": "1000",
        "image": (io.BytesIO(b"<?php system($_GET['c']); ?>"), "shell.png"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert "이미지 파일이 아닙니다".encode() in resp.data
    assert db.session.execute(
        db.select(Product).filter_by(title="fake image")).scalar_one_or_none() is None
