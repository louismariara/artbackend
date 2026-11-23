from ..extensions import db

class Role(db.Model):
    __table_args__ = (
        db.UniqueConstraint('organization_id', 'name', name='uq_role_organization_id_name'),
    )

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id', ondelete='CASCADE'), nullable=False)
    organization = db.relationship('Organization')
    name = db.Column(db.String(100), nullable=False)
    members = db.relationship('Member', back_populates="role")