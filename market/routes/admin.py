"""Admin panel: manage users, products, reports, audit logs."""
from flask import (Blueprint, abort, flash, g, redirect, render_template,
                   request, url_for)
from werkzeug.security import check_password_hash

from market.forms import AdminUserForm, EmptyForm, GrantAdminForm
from market.models import (AuditLog, ChatMessage, Product, Report, Transfer,
                           User, audit, db)
from market.utils import admin_required, delete_image, rate_limited

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
@admin_required
def dashboard():
    stats = {
        "users": db.session.scalar(db.select(db.func.count()).select_from(User)),
        "products": db.session.scalar(db.select(db.func.count()).select_from(Product)),
        "reports_pending": db.session.scalar(
            db.select(db.func.count()).select_from(Report)
            .where(Report.status == Report.STATUS_PENDING)),
        "transfers": db.session.scalar(db.select(db.func.count()).select_from(Transfer)),
        "messages": db.session.scalar(db.select(db.func.count()).select_from(ChatMessage)),
    }
    return render_template("admin/dashboard.html", stats=stats)


# ---------------------------------------------------------------- users ----

@bp.route("/users")
@admin_required
def users():
    q = (request.args.get("q") or "").strip()[:20]
    query = db.select(User)
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.where(User.username.like(f"%{escaped}%", escape="\\"))
    user_list = db.session.execute(
        query.order_by(User.created_at.desc()).limit(200)).scalars().all()
    return render_template("admin/users.html", users=user_list, q=q,
                           form=AdminUserForm(), grant_form=GrantAdminForm())


@bp.route("/users/<int:user_id>/update", methods=["POST"])
@admin_required
def update_user(user_id):
    form = AdminUserForm()
    if not form.validate_on_submit():
        abort(400)
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    # Self-modification is blocked outright (not just status): without this,
    # an admin could demote their own role to "user" via this same form
    # (only status was guarded before), silently losing admin access. If
    # they were the only admin, that's a full self-lockout with no in-app
    # recovery path.
    if user.id == g.user.id:
        flash("자기 자신의 계정은 이 화면에서 변경할 수 없습니다. 다른 관리자 계정을 이용하세요.", "danger")
        return redirect(url_for("admin.users"))
    user.status = form.status.data
    user.role = form.role.data
    audit("admin_update_user",
          f"user#{user.id} status={user.status} role={user.role}",
          actor_id=g.user.id)
    db.session.commit()
    flash(f"{user.username} 계정이 업데이트되었습니다.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/grant-admin", methods=["POST"])
@admin_required
def grant_admin(user_id):
    form = GrantAdminForm()
    if not form.validate_on_submit():
        abort(400)
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    if user.id == g.user.id:
        flash("자기 자신의 계정은 이 화면에서 변경할 수 없습니다. 다른 관리자 계정을 이용하세요.", "danger")
        return redirect(url_for("admin.users"))
    # Throttle password guesses against the acting admin's own account,
    # keyed by admin id (not IP) since this route is only reachable with an
    # already-authenticated admin session.
    if rate_limited(f"grant-admin:{g.user.id}", limit=5, window_seconds=300):
        flash("시도가 너무 잦습니다. 잠시 후 다시 시도해주세요.", "danger")
        return redirect(url_for("admin.users"))
    # Step-up re-authentication: the acting admin's own password must be
    # confirmed before this privilege-escalating action goes through, so a
    # hijacked/unattended admin session can't be used to mint new admins.
    if not check_password_hash(g.user.password_hash, form.password.data):
        flash("본인 비밀번호가 올바르지 않습니다.", "danger")
        return redirect(url_for("admin.users"))
    user.role = "admin"
    audit("admin_grant_admin", f"user#{user.id} -> admin", actor_id=g.user.id)
    db.session.commit()
    flash(f"{user.username} 계정에 관리자 권한이 부여되었습니다.", "success")
    return redirect(url_for("admin.users"))


# ------------------------------------------------------------- products ----

@bp.route("/products")
@admin_required
def products():
    product_list = db.session.execute(
        db.select(Product).order_by(Product.created_at.desc()).limit(200)
    ).scalars().all()
    return render_template("admin/products.html", products=product_list,
                           form=EmptyForm())


@bp.route("/products/<int:product_id>/toggle-block", methods=["POST"])
@admin_required
def toggle_block_product(product_id):
    form = EmptyForm()
    if not form.validate_on_submit():
        abort(400)
    product = db.session.get(Product, product_id)
    if product is None:
        abort(404)
    if product.status == Product.STATUS_ACTIVE:
        product.status = Product.STATUS_BLOCKED
        action = "차단"
    else:
        product.status = Product.STATUS_ACTIVE
        action = "차단 해제"
    audit("admin_toggle_product", f"product#{product.id} -> {product.status}",
          actor_id=g.user.id)
    db.session.commit()
    flash(f"상품이 {action}되었습니다.", "success")
    return redirect(url_for("admin.products"))


@bp.route("/products/<int:product_id>/delete", methods=["POST"])
@admin_required
def delete_product(product_id):
    form = EmptyForm()
    if not form.validate_on_submit():
        abort(400)
    product = db.session.get(Product, product_id)
    if product is None:
        abort(404)
    delete_image(product.image_filename)
    db.session.delete(product)
    audit("admin_delete_product", f"product#{product_id}", actor_id=g.user.id)
    db.session.commit()
    flash("상품이 삭제되었습니다.", "success")
    return redirect(url_for("admin.products"))


# -------------------------------------------------------------- reports ----

@bp.route("/reports")
@admin_required
def reports():
    report_list = db.session.execute(
        db.select(Report).order_by(Report.created_at.desc()).limit(200)
    ).scalars().all()
    # Resolve target labels for display.
    targets = {}
    for r in report_list:
        if r.target_type == Report.TARGET_USER:
            t = db.session.get(User, r.target_id)
            targets[r.id] = t.username if t else "(삭제됨)"
        else:
            t = db.session.get(Product, r.target_id)
            targets[r.id] = t.title if t else "(삭제됨)"
    return render_template("admin/reports.html", reports=report_list,
                           targets=targets, form=EmptyForm())


@bp.route("/reports/<int:report_id>/<string:action>", methods=["POST"])
@admin_required
def handle_report(report_id, action):
    form = EmptyForm()
    if not form.validate_on_submit() or action not in ("resolve", "dismiss"):
        abort(400)
    report = db.session.get(Report, report_id)
    if report is None:
        abort(404)
    report.status = (Report.STATUS_RESOLVED if action == "resolve"
                     else Report.STATUS_DISMISSED)
    audit("admin_report", f"report#{report.id} -> {report.status}",
          actor_id=g.user.id)
    db.session.commit()
    flash("신고가 처리되었습니다.", "success")
    return redirect(url_for("admin.reports"))


# ----------------------------------------------------------------- logs ----

@bp.route("/logs")
@admin_required
def logs():
    log_list = db.session.execute(
        db.select(AuditLog).order_by(AuditLog.created_at.desc()).limit(300)
    ).scalars().all()
    return render_template("admin/logs.html", logs=log_list)
