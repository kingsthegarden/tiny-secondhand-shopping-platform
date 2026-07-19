"""Wallet: balance, user-to-user transfers, history."""
import sqlalchemy as sa
from flask import (Blueprint, flash, g, redirect, render_template, request,
                   url_for)

from market.forms import TransferForm
from market.models import Transfer, User, audit, db
from market.utils import login_required, rate_limited

bp = Blueprint("wallet", __name__, url_prefix="/wallet")


@bp.route("/", methods=["GET", "POST"])
@login_required
def index():
    form = TransferForm()
    # Allow ?to=<username> prefill from profile pages (GET only).
    if request.method == "GET" and request.args.get("to"):
        form.receiver.data = request.args.get("to")[:20]

    if form.validate_on_submit():
        _do_transfer(form)
        return redirect(url_for("wallet.index"))

    history = db.session.execute(
        db.select(Transfer)
        .where(sa.or_(Transfer.sender_id == g.user.id,
                      Transfer.receiver_id == g.user.id))
        .order_by(Transfer.created_at.desc()).limit(50)).scalars().all()
    return render_template("wallet/index.html", form=form, history=history)


def _do_transfer(form):
    amount = form.amount.data
    receiver = db.session.execute(
        db.select(User).filter_by(username=form.receiver.data)).scalar_one_or_none()

    if receiver is None:
        flash("받는 사람을 찾을 수 없습니다.", "danger")
        return
    if receiver.id == g.user.id:
        flash("자기 자신에게는 송금할 수 없습니다.", "danger")
        return
    if not receiver.is_active_user:
        flash("해당 사용자에게 송금할 수 없습니다.", "danger")
        return
    if rate_limited(f"transfer:{g.user.id}", limit=5, window_seconds=60):
        flash("송금 시도가 너무 잦습니다. 잠시 후 다시 시도해주세요.", "danger")
        return

    # Race-condition-safe debit: the balance check and subtraction happen in
    # a single conditional UPDATE, so two concurrent transfers cannot both
    # spend the same money (no TOCTOU / double-spend).
    result = db.session.execute(
        sa.update(User)
        .where(User.id == g.user.id, User.balance >= amount)
        .values(balance=User.balance - amount))
    if result.rowcount != 1:
        db.session.rollback()
        flash("잔액이 부족합니다.", "danger")
        return
    db.session.execute(
        sa.update(User)
        .where(User.id == receiver.id)
        .values(balance=User.balance + amount))
    db.session.add(Transfer(sender_id=g.user.id, receiver_id=receiver.id,
                            amount=amount, memo=form.memo.data or ""))
    audit("transfer", f"to={receiver.username} amount={amount}", actor_id=g.user.id)
    db.session.commit()
    flash(f"{receiver.username}님에게 {amount:,}원을 송금했습니다.", "success")
