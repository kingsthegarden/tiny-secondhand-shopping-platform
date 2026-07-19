import os
import re
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from market import create_app
from market.models import User, db
from werkzeug.security import generate_password_hash


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    # CSRF stays ENABLED: tests exercise the app with real protections on.
    WTF_CSRF_ENABLED = True
    UPLOAD_FOLDER = tempfile.mkdtemp(prefix="market-test-uploads-")


@pytest.fixture()
def app():
    # The in-memory rate limiter is process-global; reset it between tests
    # so per-IP login limits don't leak across test cases.
    from market import utils
    utils._rate_buckets.clear()

    app = create_app(TestConfig)

    @app.after_request
    def _reset_csrf_cache(resp):
        # The fixture keeps one app context open for the whole test, so
        # test-client requests share that context's `g`. Flask-WTF caches
        # the signed CSRF token on g per request; without this reset, a
        # stale token from before login leaks into later responses.
        from flask import g
        g.pop("csrf_token", None)
        return resp

    with app.app_context():
        db.drop_all()
        db.create_all()
        # seed: normal users + admin
        for name, role in [("alice", "user"), ("bob", "user"), ("admin1", "admin")]:
            db.session.add(User(
                username=name,
                password_hash=generate_password_hash("TestPass921"),
                role=role, balance=100_000))
        db.session.commit()
        yield app
        db.session.remove()


@pytest.fixture()
def client(app):
    return app.test_client()


CSRF_RE = re.compile(rb'name="csrf_token"[^>]*value="([^"]+)"')


def get_csrf(client, url):
    resp = client.get(url)
    m = CSRF_RE.search(resp.data)
    assert m, f"no csrf token found on {url}"
    return m.group(1).decode()


def login(client, username="alice", password="TestPass921"):
    token = get_csrf(client, "/login")
    return client.post("/login", data={
        "csrf_token": token, "username": username, "password": password,
    }, follow_redirects=True)
