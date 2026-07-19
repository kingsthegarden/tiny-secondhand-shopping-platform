"""User profiles and my-page (bio / password update)."""
from flask import (Blueprint, abort, flash, g, redirect, render_template,
                   url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from market.forms import BioForm, PasswordChangeForm
from market.models import Product, User, audit, db
from market.utils import login_required

bp = Blueprint("users", __name__, url_prefix="/users")


@bp.route("/<int:user_id>")
@login_required
def profile(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    products = db.session.execute(
        db.select(Product)
        .filter_by(seller_id=user.id, status=Product.STATUS_ACTIVE)
        .order_by(Product.created_at.desc()).limit(50)).scalars().all()
    return render_template("users/profile.html", user=user, products=products)


@bp.route("/me", methods=["GET", "POST"])
@login_required
def mypage():
    bio_form = BioForm(obj=g.user)
    pw_form = PasswordChangeForm()
    return render_template("users/mypage.html", bio_form=bio_form, pw_form=pw_form)


@bp.route("/me/bio", methods=["POST"])
@login_required
def update_bio():
    bio_form = BioForm()
    if bio_form.validate_on_submit():
        g.user.bio = bio_form.bio.data or ""
        db.session.commit()
        flash("소개글이 수정되었습니다.", "success")
        return redirect(url_for("users.mypage"))
    pw_form = PasswordChangeForm()
    return render_template("users/mypage.html", bio_form=bio_form, pw_form=pw_form)


@bp.route("/me/password", methods=["POST"])
@login_required
def update_password():
    pw_form = PasswordChangeForm()
    if pw_form.validate_on_submit():
        # Re-authentication before a sensitive change: require the current
        # password (mitigates session hijacking / unattended session abuse).
        if not check_password_hash(g.user.password_hash,
                                   pw_form.current_password.data):
            flash("현재 비밀번호가 올바르지 않습니다.", "danger")
        elif pw_form.current_password.data == pw_form.new_password.data:
            flash("새 비밀번호가 기존 비밀번호와 같습니다.", "warning")
        else:
            g.user.password_hash = generate_password_hash(pw_form.new_password.data)
            audit("password_change", actor_id=g.user.id)
            db.session.commit()
            flash("비밀번호가 변경되었습니다.", "success")
        return redirect(url_for("users.mypage"))
    bio_form = BioForm(obj=g.user)
    return render_template("users/mypage.html", bio_form=bio_form, pw_form=pw_form)
