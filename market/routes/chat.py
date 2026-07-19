"""Chat pages (message delivery happens over Socket.IO, see sockets.py)."""
from flask import Blueprint, abort, g, render_template

from market.models import ChatMessage, User, db
from market.utils import dm_room_name, login_required, parse_dm_room

bp = Blueprint("chat", __name__, url_prefix="/chat")


def _recent_messages(room, limit=50):
    msgs = db.session.execute(
        db.select(ChatMessage).filter_by(room=room)
        .order_by(ChatMessage.created_at.desc()).limit(limit)).scalars().all()
    return list(reversed(msgs))


@bp.route("/")
@login_required
def global_chat():
    messages = _recent_messages("global")
    return render_template("chat/global.html", messages=messages)


@bp.route("/dm")
@login_required
def dm_list():
    """List of 1:1 conversations the current user participates in."""
    rooms = db.session.execute(
        db.select(ChatMessage.room)
        .where(ChatMessage.room.like("dm:%")).distinct()).scalars().all()
    partner_ids = set()
    for room in rooms:
        ids = parse_dm_room(room)
        if ids and g.user.id in ids:
            partner_ids.add(ids[0] if ids[1] == g.user.id else ids[1])
    partners = []
    if partner_ids:
        partners = db.session.execute(
            db.select(User).where(User.id.in_(partner_ids))).scalars().all()
    return render_template("chat/dm_list.html", partners=partners)


@bp.route("/dm/<int:user_id>")
@login_required
def dm(user_id):
    if user_id == g.user.id:
        abort(400)
    partner = db.session.get(User, user_id)
    if partner is None:
        abort(404)
    room = dm_room_name(g.user.id, user_id)
    messages = _recent_messages(room)
    return render_template("chat/dm.html", partner=partner, room=room,
                           messages=messages)
