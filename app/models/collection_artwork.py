from ..extensions import db

class CollectionArtwork(db.Model):
    __tablename__ = 'collection_artwork'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id', ondelete='CASCADE'), nullable=False)
    organization = db.relationship('Organization')
    collection_id = db.Column(db.Integer, db.ForeignKey('collection.id'), nullable=False)
    artwork_id = db.Column(db.Integer, db.ForeignKey('artworks.id'), nullable=False)
    added_at = db.Column(db.DateTime, server_default=db.func.now())

    __table_args__ = (
        db.UniqueConstraint('collection_id', 'artwork_id', name='unique_collection_artwork'),
    )