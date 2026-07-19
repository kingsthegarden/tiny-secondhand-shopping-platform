"""Socket.IO handlers for the real-time global chat and 1:1 DMs.

Security notes:
- Every event re-checks the session (authentication) server-side; the client
  never supplies its own identity.
- Room membership is validated on join AND on send (authorization).
- Message content is length-limited and rate-limited server-side; rendering
  on the client uses textContent (never innerHTML), so chat is XSS-safe.
"""
from flask import request, session
from flask_socketio import emit, join_room

from market import socketio
from market.models import ChatMessage, User, db
from market.utils import rate_limited, user_in_room


def _current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    user = db.session.get(User, user_id)
    if user is None or not user.is_active_user:
        return None
    return user


@socketio.on("connect")
def on_connect():
    # Reject unauthenticated socket connections outright.
    if _current_user() is None:
        return False
    return True


@socketio.on("join")
def on_join(data):
    user = _current_user()
    if user is None:
        return
    room = str((data or {}).get("room", ""))[:50]
    # Authorization: only 'global' or a DM room the user belongs to.
    if not user_in_room(room, user.id):
        return
    join_room(room)


@socketio.on("send_message")
def on_send_message(data):
    user = _current_user()
    if user is None:
        return
    data = data or {}
    room = str(data.get("room", ""))[:50]
    content = str(data.get("content", "")).strip()

    if not user_in_room(room, user.id):
        return
    if not content or len(content) > 500:
        emit("error_message", {"error": "메시지는 1~500자여야 합니다."},
             to=request.sid)
        return
    from flask import current_app
    if rate_limited(f"chat:{user.id}",
                    limit=current_app.config["CHAT_RATE_LIMIT"],
                    window_seconds=current_app.config["CHAT_RATE_WINDOW"]):
        emit("error_message", {"error": "메시지를 너무 빠르게 보내고 있습니다."},
             to=request.sid)
        return

    msg = ChatMessage(room=room, sender_id=user.id, content=content)
    db.session.add(msg)
    db.session.commit()

    emit("new_message", {
        "sender": user.username,
        "sender_id": user.id,
        "content": content,
        "time": msg.created_at.strftime("%H:%M"),
    }, to=room)
