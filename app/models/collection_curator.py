from ..extensions import db

class CollectionCurator(db.Model):
    __tablename__ = 'collection_curator'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id', ondelete='CASCADE'), nullable=False)
    organization = db.relationship('Organization')
    collection_id = db.Column(db.Integer, db.ForeignKey('collection.id'), nullable=False)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'), nullable=False)
    added_at = db.Column(db.DateTime, server_default=db.func.now())

    __table_args__ = (
        db.UniqueConstraint('collection_id', 'member_id', name='unique_collection_curator'),
    )