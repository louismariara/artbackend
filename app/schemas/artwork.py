from ..extensions import ma
from ..models.artwork import Artwork
from marshmallow import fields

class ArtworkSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Artwork
        load_instance = True
        fields = ('id', 'title', 'artist', 'medium', 'dimensions', 'condition', 'location', 'theme', 'views', 'updated_at', 'member_id', 'image_path', 'description')
        include_fk = True

    member_id = fields.Integer(allow_none=True)