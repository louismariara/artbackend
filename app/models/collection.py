from ..extensions import db

class Collection(db.Model):
    __tablename__ = 'collection'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id', ondelete='CASCADE'), nullable=False)
    organization = db.relationship('Organization')
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    theme = db.Column(db.String(200), nullable=True)
    curator_id = db.Column(db.Integer, db.ForeignKey('member.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())