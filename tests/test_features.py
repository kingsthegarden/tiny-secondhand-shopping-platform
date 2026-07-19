"""Functional tests: minimum platform requirements work end-to-end."""
from market.models import Product, User, db
from tests.conftest import get_csrf, login


def test_register_and_login_flow(client):
    token = get_csrf(client, "/register")
    resp = client.post("/register", data={
        "csrf_token": token, "username": "charlie",
        "password": "TestPass921", "password2": "TestPass921"},
        follow_redirects=True)
    assert "회원가입이 완료".encode() in resp.data
    resp = login(client, username="charlie")
    assert "로그아웃".encode() in resp.data


def test_duplicate_username_rejected(client):
    token = get_csrf(client, "/register")
    resp = client.post("/register", data={
        "csrf_token": token, "username": "alice",
        "password": "TestPass921", "password2": "TestPass921"})
    assert "이미 사용 중인 아이디".encode() in resp.data


def test_product_create_list_search_detail(client):
    login(client)
    token = get_csrf(client, "/products/new")
    client.post("/products/new", data={
        "csrf_token": token, "title": "아이폰 15", "description": "새것 같음",
        "price": "800000"}, follow_redirects=True)

    # list shows the name only (with a link), not the description
    resp = client.get("/products")
    assert "아이폰 15".encode() in resp.data
    assert "새것 같음".encode() not in resp.data

    # search finds it
    resp = client.get("/products?q=아이폰")
    assert "아이폰 15".encode() in resp.data

    # detail shows description and price
    product = db.session.execute(
        db.select(Product).filter_by(title="아이폰 15")).scalar_one()
    resp = client.get(f"/products/{product.id}")
    assert "새것 같음".encode() in resp.data
    assert b"800,000" in resp.data


def test_mypage_bio_and_password_update(client):
    login(client)
    token = get_csrf(client, "/users/me")
    client.post("/users/me/bio", data={"csrf_token": token, "bio": "안녕하세요!"},
                follow_redirects=True)
    user = db.session.execute(db.select(User).filter_by(username="alice")).scalar_one()
    assert user.bio == "안녕하세요!"

    token = get_csrf(client, "/users/me")
    resp = client.post("/users/me/password", data={
        "csrf_token": token, "current_password": "TestPass921",
        "new_password": "NewPassw0rd2", "new_password2": "NewPassw0rd2"},
        follow_redirects=True)
    assert "비밀번호가 변경되었습니다".encode() in resp.data
    # old password no longer works, new one does
    client.post("/logout", data={"csrf_token": get_csrf(client, "/users/me")})
    resp = login(client, password="TestPass921")
    assert "올바르지 않습니다".encode() in resp.data
    resp = login(client, password="NewPassw0rd2")
    assert "로그아웃".encode() in resp.data


def test_password_change_requires_current_password(client):
    login(client)
    token = get_csrf(client, "/users/me")
    resp = client.post("/users/me/password", data={
        "csrf_token": token, "current_password": "WrongPw999",
        "new_password": "NewPassw0rd2", "new_password2": "NewPassw0rd2"},
        follow_redirects=True)
    assert "현재 비밀번호가 올바르지 않습니다".encode() in resp.data


def test_profile_page_visible(client):
    login(client)
    bob = db.session.execute(db.select(User).filter_by(username="bob")).scalar_one()
    resp = client.get(f"/users/{bob.id}")
    assert b"bob" in resp.data
    assert "1:1 채팅".encode() in resp.data


def test_admin_can_manage(app, client):
    login(client, username="admin1")
    assert client.get("/admin/").status_code == 200

    # admin blocks a product
    alice = db.session.execute(db.select(User).filter_by(username="alice")).scalar_one()
    product = Product(title="target", description="d", price=1, seller_id=alice.id)
    db.session.add(product)
    db.session.commit()
    token = get_csrf(client, "/admin/products")
    client.post(f"/admin/products/{product.id}/toggle-block",
                data={"csrf_token": token}, follow_redirects=True)
    db.session.expire_all()
    assert product.status == Product.STATUS_BLOCKED

    # admin makes a user dormant
    token = get_csrf(client, "/admin/users")
    client.post(f"/admin/users/{alice.id}/update", data={
        "csrf_token": token, "status": "dormant", "role": "user"},
        follow_redirects=True)
    db.session.expire_all()
    assert alice.status == User.STATUS_DORMANT
