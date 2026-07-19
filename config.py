"""Application configuration.

Security-relevant settings are centralized here so they can be reviewed
and adjusted in one place.
"""
import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")


def _load_secret_key() -> str:
    """Load SECRET_KEY from the environment, or generate one and persist it.

    A hard-coded secret key in source code is a security weakness (session
    forgery). We read it from the environment first; otherwise a random key
    is generated once and stored outside version control (instance/).
    """
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    key_path = os.path.join(INSTANCE_DIR, "secret.key")
    if os.path.exists(key_path):
        with open(key_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key)
    return key


class Config:
    SECRET_KEY = _load_secret_key()

    # --- Database ---
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(INSTANCE_DIR, "market.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Session / cookie security ---
    SESSION_COOKIE_HTTPONLY = True          # JS cannot read the session cookie (XSS mitigation)
    SESSION_COOKIE_SAMESITE = "Lax"         # CSRF mitigation (defense in depth with CSRF tokens)
    # Set SESSION_COOKIE_SECURE=1 when serving over HTTPS (e.g. behind ngrok)
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
    PERMANENT_SESSION_LIFETIME = 1800       # 30 min idle timeout

    # --- CSRF ---
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # --- Uploads ---
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024    # 2MB request cap (upload DoS mitigation)
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "market", "static", "uploads")
    ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

    # --- Business rules ---
    STARTING_BALANCE = 100_000              # demo wallet balance for new users (KRW)
    MAX_TRANSFER_AMOUNT = 10_000_000
    MAX_PRICE = 100_000_000
    PRODUCT_BLOCK_REPORT_THRESHOLD = 3      # distinct reporters before a product is blocked
    USER_DORMANT_REPORT_THRESHOLD = 5       # distinct reporters before a user goes dormant

    # --- Login defense ---
    LOGIN_MAX_FAILURES = 5                  # failures before temporary lockout
    LOGIN_LOCKOUT_SECONDS = 300             # 5 min lockout

    # --- Chat ---
    CHAT_MAX_LENGTH = 500
    CHAT_RATE_LIMIT = 5                     # messages
    CHAT_RATE_WINDOW = 3                    # per N seconds
