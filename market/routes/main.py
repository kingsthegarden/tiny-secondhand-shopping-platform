"""Index + product list/search (public pages)."""
from flask import Blueprint, render_template, request

from market.models import Product, db

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/products")
def product_list():
    """Product list: shows names only; click through for details.

    Search uses a bound LIKE parameter with escaped wildcards -> no SQL
    injection, and '%'/'_' in user input are treated literally.
    """
    q = (request.args.get("q") or "").strip()[:100]
    query = db.select(Product).filter_by(status=Product.STATUS_ACTIVE)
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.filter(Product.title.like(f"%{escaped}%", escape="\\"))
    products = db.session.execute(
        query.order_by(Product.created_at.desc()).limit(200)).scalars().all()
    return render_template("products/list.html", products=products, q=q)
