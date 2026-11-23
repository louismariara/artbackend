from ..extensions import db

class Wishlist(db.Model):
    __tablename__ = 'wishlist'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id', ondelete='CASCADE'), nullable=False)
    organization = db.relationship('Organization')
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'), nullable=False)
    artwork_id = db.Column(db.Integer, db.ForeignKey('artworks.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    __table_args__ = (
        db.UniqueConstraint('member_id', 'artwork_id', name='unique_wishlist_entry'),
    )