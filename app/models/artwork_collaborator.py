from ..extensions import db

class ArtworkCollaborator(db.Model):
    __tablename__ = 'artwork_collaborator'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id', ondelete='CASCADE'), nullable=False)
    organization = db.relationship('Organization')
    artwork_id = db.Column(db.Integer, db.ForeignKey('artworks.id'), nullable=False)
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'), nullable=False)
    added_at = db.Column(db.DateTime, server_default=db.func.now())

    __table_args__ = (
        db.UniqueConstraint('artwork_id', 'member_id', name='unique_artwork_collaborator'),
    )