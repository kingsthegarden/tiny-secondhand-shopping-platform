"""Database models.

All queries in the application go through SQLAlchemy ORM / bound
parameters, which prevents SQL injection by construction.
"""
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model):
    __tablename__ = "users"

    STATUS_ACTIVE = "active"
    STATUS_DORMANT = "dormant"    # auto: too many reports / admin action
    STATUS_BANNED = "banned"      # admin action

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    bio = db.Column(db.String(500), nullable=False, default="")
    role = db.Column(db.String(10), nullable=False, default="user")  # user | admin
    status = db.Column(db.String(10), nullable=False, default=STATUS_ACTIVE)
    balance = db.Column(db.Integer, nullable=False, default=0)
    failed_logins = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    products = db.relationship("Product", backref="seller", lazy="dynamic")

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_active_user(self) -> bool:
        return self.status == self.STATUS_ACTIVE


class Product(db.Model):
    __tablename__ = "products"

    STATUS_ACTIVE = "active"
    STATUS_BLOCKED = "blocked"    # auto: too many reports / admin action

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False, index=True)
    description = db.Column(db.String(2000), nullable=False, default="")
    price = db.Column(db.Integer, nullable=False)
    image_filename = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(10), nullable=False, default=STATUS_ACTIVE)
    seller_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class Report(db.Model):
    __tablename__ = "reports"
    # A user can report a given target only once (report-spam prevention).
    __table_args__ = (
        db.UniqueConstraint("reporter_id", "target_type", "target_id",
                            name="uq_report_once"),
    )

    TARGET_USER = "user"
    TARGET_PRODUCT = "product"
    STATUS_PENDING = "pending"
    STATUS_RESOLVED = "resolved"
    STATUS_DISMISSED = "dismissed"

    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    target_type = db.Column(db.String(10), nullable=False)
    target_id = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(10), nullable=False, default=STATUS_PENDING)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    reporter = db.relationship("User", foreign_keys=[reporter_id])


class ChatMessage(db.Model):
    __tablename__ = "chat_messages"

    id = db.Column(db.Integer, primary_key=True)
    room = db.Column(db.String(50), nullable=False, index=True)  # "global" or "dm:<lo>:<hi>"
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    sender = db.relationship("User")


class Transfer(db.Model):
    __tablename__ = "transfers"

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    amount = db.Column(db.Integer, nullable=False)
    memo = db.Column(db.String(100), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    sender = db.relationship("User", foreign_keys=[sender_id])
    receiver = db.relationship("User", foreign_keys=[receiver_id])


class AuditLog(db.Model):
    """Security-relevant events (logins, blocks, admin actions...)."""
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, nullable=True)   # None for anonymous/system
    action = db.Column(db.String(50), nullable=False)
    detail = db.Column(db.String(500), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


def audit(action: str, detail: str = "", actor_id=None):
    db.session.add(AuditLog(actor_id=actor_id, action=action, detail=detail[:500]))
