"""Product registration / detail / owner management."""
from flask import (Blueprint, abort, flash, g, redirect, render_template,
                   url_for)

from market.forms import EmptyForm, ProductForm
from market.models import Product, audit, db
from market.utils import delete_image, login_required, save_image

bp = Blueprint("products", __name__, url_prefix="/products")


@bp.route("/new", methods=["GET", "POST"])
@login_required
def new():
    form = ProductForm()
    if form.validate_on_submit():
        image_filename = None
        if form.image.data:
            try:
                image_filename = save_image(form.image.data)
            except ValueError as e:
                flash(str(e), "danger")
                return render_template("products/form.html", form=form, mode="new")
        product = Product(
            title=form.title.data,
            description=form.description.data,
            price=form.price.data,
            image_filename=image_filename,
            seller_id=g.user.id,
        )
        db.session.add(product)
        audit("product_create", f"title={form.title.data[:50]}", actor_id=g.user.id)
        db.session.commit()
        flash("상품이 등록되었습니다.", "success")
        return redirect(url_for("products.detail", product_id=product.id))
    return render_template("products/form.html", form=form, mode="new")


@bp.route("/<int:product_id>")
def detail(product_id):
    product = db.session.get(Product, product_id)
    if product is None:
        abort(404)
    # Blocked products are hidden from everyone except the owner and admins.
    is_owner = g.user is not None and g.user.id == product.seller_id
    is_admin = g.user is not None and g.user.is_admin
    if product.status != Product.STATUS_ACTIVE and not (is_owner or is_admin):
        abort(404)
    return render_template("products/detail.html", product=product,
                           is_owner=is_owner, form=EmptyForm())


@bp.route("/mine")
@login_required
def mine():
    products = db.session.execute(
        db.select(Product).filter_by(seller_id=g.user.id)
        .order_by(Product.created_at.desc())).scalars().all()
    return render_template("products/mine.html", products=products, form=EmptyForm())


def _owned_product_or_403(product_id):
    """IDOR defense: only the owner (or an admin) may modify a product."""
    product = db.session.get(Product, product_id)
    if product is None:
        abort(404)
    if product.seller_id != g.user.id and not g.user.is_admin:
        abort(403)
    return product


@bp.route("/<int:product_id>/edit", methods=["GET", "POST"])
@login_required
def edit(product_id):
    product = _owned_product_or_403(product_id)
    form = ProductForm(obj=product)
    if form.validate_on_submit():
        product.title = form.title.data
        product.description = form.description.data
        product.price = form.price.data
        if form.image.data:
            try:
                new_file = save_image(form.image.data)
            except ValueError as e:
                flash(str(e), "danger")
                return render_template("products/form.html", form=form,
                                       mode="edit", product=product)
            delete_image(product.image_filename)
            product.image_filename = new_file
        audit("product_edit", f"id={product.id}", actor_id=g.user.id)
        db.session.commit()
        flash("상품 정보가 수정되었습니다.", "success")
        return redirect(url_for("products.detail", product_id=product.id))
    return render_template("products/form.html", form=form, mode="edit",
                           product=product)


@bp.route("/<int:product_id>/delete", methods=["POST"])
@login_required
def delete(product_id):
    form = EmptyForm()
    if not form.validate_on_submit():
        abort(400)
    product = _owned_product_or_403(product_id)
    delete_image(product.image_filename)
    db.session.delete(product)
    audit("product_delete", f"id={product_id}", actor_id=g.user.id)
    db.session.commit()
    flash("상품이 삭제되었습니다.", "success")
    return redirect(url_for("products.mine"))
