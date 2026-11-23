from ..extensions import db

class SuperAdminSession(db.Model):
    __tablename__ = 'super_admin_session'

    id = db.Column(db.Integer, primary_key=True)
    super_admin_id = db.Column(db.Integer, db.ForeignKey('super_admin.id', ondelete='CASCADE'), nullable=False)
    jti = db.Column(db.String(255), nullable=False, unique=True)
    device_info = db.Column(db.String(500), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    revoked = db.Column(db.Boolean, default=False, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revoked_by = db.Column(db.String(20), nullable=True)