"""Reporting bad users/products + automatic sanctions."""
from flask import (Blueprint, abort, current_app, flash, g, redirect,
                   render_template, url_for)

from market.forms import ReportForm
from market.models import Product, Report, User, audit, db
from market.utils import login_required, rate_limited

bp = Blueprint("reports", __name__, url_prefix="/report")


def _get_target(target_type, target_id):
    if target_type == Report.TARGET_USER:
        target = db.session.get(User, target_id)
        label = target.username if target else None
    elif target_type == Report.TARGET_PRODUCT:
        target = db.session.get(Product, target_id)
        label = target.title if target else None
    else:
        return None, None
    return target, label


@bp.route("/<target_type>/<int:target_id>", methods=["GET", "POST"])
@login_required
def report(target_type, target_id):
    target, label = _get_target(target_type, target_id)
    if target is None:
        abort(404)
    if target_type == Report.TARGET_USER and target.id == g.user.id:
        flash("자기 자신은 신고할 수 없습니다.", "danger")
        return redirect(url_for("main.index"))
    if (target_type == Report.TARGET_PRODUCT
            and target.seller_id == g.user.id):
        flash("자신의 상품은 신고할 수 없습니다.", "danger")
        return redirect(url_for("main.index"))

    form = ReportForm()
    if form.validate_on_submit():
        # Duplicate report check (also enforced by DB unique constraint).
        dup = db.session.execute(
            db.select(Report).filter_by(
                reporter_id=g.user.id, target_type=target_type,
                target_id=target_id)).scalar_one_or_none()
        if dup:
            flash("이미 신고한 대상입니다.", "warning")
            return redirect(url_for("main.index"))
        if rate_limited(f"report:{g.user.id}", limit=5, window_seconds=3600):
            flash("신고가 너무 잦습니다. 잠시 후 다시 시도해주세요.", "danger")
            return redirect(url_for("main.index"))

        db.session.add(Report(reporter_id=g.user.id, target_type=target_type,
                              target_id=target_id, reason=form.reason.data))
        audit("report", f"{target_type}#{target_id}", actor_id=g.user.id)
        db.session.flush()
        _apply_auto_sanctions(target_type, target_id)
        db.session.commit()
        flash("신고가 접수되었습니다.", "success")
        return redirect(url_for("main.index"))
    return render_template("reports/form.html", form=form,
                           target_type=target_type, label=label)


def _apply_auto_sanctions(target_type, target_id):
    """Block products / put users to sleep once report thresholds are hit.

    The unique constraint guarantees each row is a distinct reporter, so a
    single user cannot trigger a sanction alone. Dismissed reports don't count.
    """
    count = db.session.execute(
        db.select(db.func.count()).select_from(Report)
        .where(Report.target_type == target_type,
               Report.target_id == target_id,
               Report.status != Report.STATUS_DISMISSED)).scalar_one()

    if target_type == Report.TARGET_PRODUCT:
        if count >= current_app.config["PRODUCT_BLOCK_REPORT_THRESHOLD"]:
            product = db.session.get(Product, target_id)
            if product and product.status == Product.STATUS_ACTIVE:
                product.status = Product.STATUS_BLOCKED
                audit("auto_block_product", f"product#{target_id} reports={count}")
    else:
        if count >= current_app.config["USER_DORMANT_REPORT_THRESHOLD"]:
            user = db.session.get(User, target_id)
            if user and user.status == User.STATUS_ACTIVE and not user.is_admin:
                user.status = User.STATUS_DORMANT
                audit("auto_dormant_user", f"user#{target_id} reports={count}")
