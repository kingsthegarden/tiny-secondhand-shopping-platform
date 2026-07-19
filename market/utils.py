"""Shared helpers: auth decorators, rate limiting, secure file upload."""
import functools
import os
import secrets
import threading
import time
from collections import defaultdict, deque

from flask import abort, current_app, flash, g, redirect, request, url_for


# ---------------------------------------------------------------------------
# Access control decorators
# ---------------------------------------------------------------------------

def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("로그인이 필요합니다.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("로그인이 필요합니다.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        if not g.user.is_admin:
            # 403 (not 404) is fine here; existence of /admin is not a secret.
            abort(403)
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# In-memory rate limiter (per-process). Keeps a sliding window of timestamps.
# ---------------------------------------------------------------------------

_rate_lock = threading.Lock()
_rate_buckets: dict = defaultdict(deque)


def rate_limited(key: str, limit: int, window_seconds: int) -> bool:
    """Return True if `key` exceeded `limit` events per `window_seconds`."""
    now = time.monotonic()
    with _rate_lock:
        bucket = _rate_buckets[key]
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()
        if len(bucket) >= limit:
            return True
        bucket.append(now)
        return False


# ---------------------------------------------------------------------------
# Secure image upload
# ---------------------------------------------------------------------------

# Magic-byte signatures: the file content must actually be an image, not just
# have an image extension (prevents e.g. uploading .php/.html renamed to .png).
_IMAGE_SIGNATURES = (
    (b"\xff\xd8\xff", "jpg"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
)


def _sniff_image(header: bytes):
    for sig, kind in _IMAGE_SIGNATURES:
        if header.startswith(sig):
            return kind
    # WEBP: RIFF....WEBP
    if header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "webp"
    return None


def save_image(file_storage):
    """Validate and store an uploaded image.

    Returns the stored filename, or raises ValueError with a user-safe message.
    Defenses: extension allowlist, magic-byte content check, randomized
    server-side filename (no user-controlled path components), size cap via
    MAX_CONTENT_LENGTH.
    """
    filename = file_storage.filename or ""
    if "." not in filename:
        raise ValueError("파일 확장자가 없습니다.")
    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in current_app.config["ALLOWED_IMAGE_EXTENSIONS"]:
        raise ValueError("허용되지 않는 파일 형식입니다.")

    header = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    kind = _sniff_image(header)
    if kind is None:
        raise ValueError("이미지 파일이 아닙니다.")

    # Never trust the client filename: generate a random name server-side.
    stored = f"{secrets.token_hex(16)}.{kind if kind != 'jpg' else 'jpg'}"
    upload_dir = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_dir, exist_ok=True)
    file_storage.save(os.path.join(upload_dir, stored))
    return stored


def delete_image(filename: str):
    """Remove a stored upload; ignores missing files and path tricks."""
    if not filename:
        return
    # basename() strips any directory components as defense-in-depth
    safe = os.path.basename(filename)
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], safe)
    if os.path.isfile(path):
        os.remove(path)


# ---------------------------------------------------------------------------
# Chat room helpers
# ---------------------------------------------------------------------------

def dm_room_name(user_a_id: int, user_b_id: int) -> str:
    lo, hi = sorted((int(user_a_id), int(user_b_id)))
    return f"dm:{lo}:{hi}"


def parse_dm_room(room: str):
    """Return (lo, hi) user ids for a dm room string, or None if invalid."""
    parts = room.split(":")
    if len(parts) != 3 or parts[0] != "dm":
        return None
    try:
        lo, hi = int(parts[1]), int(parts[2])
    except ValueError:
        return None
    if lo >= hi:
        return None
    return lo, hi


def user_in_room(room: str, user_id: int) -> bool:
    """Server-side authorization check for chat rooms."""
    if room == "global":
        return True
    ids = parse_dm_room(room)
    return ids is not None and user_id in ids
