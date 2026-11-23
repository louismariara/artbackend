from ..extensions import db

class Artwork(db.Model):
    __tablename__ = 'artworks'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id', ondelete='CASCADE'), nullable=False)
    organization = db.relationship('Organization')
    title = db.Column(db.String(200), nullable=False, index=True)
    artist = db.Column(db.String(100), nullable=False, index=True)
    medium = db.Column(db.String(100))
    dimensions = db.Column(db.String(100))
    condition = db.Column(db.String(50))
    location = db.Column(db.String(255))
    theme = db.Column(db.String(100), index=True)
    views = db.Column(db.Integer, default=0)
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    member_id = db.Column(db.Integer, db.ForeignKey('member.id'), nullable=True)
    member = db.relationship('Member', back_populates='artworks')
    image_path = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Numeric(10, 2), nullable=True)
    category = db.Column(db.String(100), nullable=True)

    def __repr__(self):
        return f'<Artwork {self.title} by {self.artist}>'