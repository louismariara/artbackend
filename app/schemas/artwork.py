from ..extensions import ma
from ..models.artwork import Artwork
from ..models.member import Member
from marshmallow import fields

class ArtworkSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Artwork
        load_instance = True
        fields = ('id', 'title', 'artist', 'medium', 'dimensions', 'condition', 'location', 'theme', 'views', 'updated_at', 'member_id', 'uploaded_by', 'image_path', 'description', 'price', 'category')
        include_fk = True

    member_id = fields.Integer(allow_none=True)
    uploaded_by = fields.Method("get_uploader_name")

    def get_uploader_name(self, obj):
        if obj.member_id:
            member = Member.query.get(obj.member_id)
            return member.name if member else "Unknown"
        return None