from ..extensions import db

class Member(db.Model):
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'email', name='uq_member_organization_id_email'),
    )

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id', ondelete='CASCADE'), nullable=False)
    organization = db.relationship("Organization", back_populates="members")
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(500), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id', ondelete='CASCADE'), nullable=False)
    role = db.relationship("Role", back_populates="members")
    artworks = db.relationship('Artwork', back_populates='member')
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    otp_code_hash = db.Column(db.String(255), nullable=True)
    otp_expires_at = db.Column(db.DateTime, nullable=True)
    otp_attempts = db.Column(db.Integer, default=0)
    admin_locked = db.Column(db.Boolean, default=False, nullable=False)
    unlock_attempts = db.Column(db.Integer, default=0, nullable=False) 
    email_rate_violations = db.Column(db.Integer, default=0, nullable=False)
    email_rate_locked_until = db.Column(db.DateTime, nullable=True)
    ip_rate_violations = db.Column(db.Integer, default=0, nullable=False)
    ip_rate_locked_until = db.Column(db.DateTime, nullable=True)
    tokens_valid_after = db.Column(db.DateTime, nullable=True)
    password_reset_token = db.Column(db.String(255), nullable=True)
    password_reset_expires = db.Column(db.DateTime, nullable=True)