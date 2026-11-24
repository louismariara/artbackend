from datetime import datetime, timezone
from ..extensions import db

class Organization(db.Model):
    __tablename__ = 'organization'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    slug = db.Column(db.String(150), nullable=False, unique=True)
    status = db.Column(db.String(20), nullable=False, default='active')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    # Last day the gallery has paid for. Empty until a super admin records it.
    paid_until = db.Column(db.Date, nullable=True)
    # Why a gallery is suspended: "lease" (the paid-through date passed) or
    # "manual" (a super admin turned it off). Empty while the gallery is active.
    suspended_reason = db.Column(db.String(20), nullable=True)
    logo_path = db.Column(db.String(255), nullable=True)
    background_path = db.Column(db.String(255), nullable=True)
    # Keys from the appearance font list. Empty means the standard typeface.
    font_heading = db.Column(db.String(40), nullable=True)
    font_body = db.Column(db.String(40), nullable=True)
    # Key from the appearance currency list. Empty means Kenyan shillings.
    currency = db.Column(db.String(10), nullable=True)
    # Color keys from the appearance list. Empty means the standard palette.
    color_accent = db.Column(db.String(20), nullable=True)
    color_button = db.Column(db.String(20), nullable=True)
    color_heading = db.Column(db.String(20), nullable=True)
    # Top bar color. Empty means charcoal.
    color_bar = db.Column(db.String(20), nullable=True)

    members = db.relationship('Member', back_populates='organization')