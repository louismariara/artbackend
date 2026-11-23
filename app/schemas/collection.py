from ..extensions import ma
from ..models.collection import Collection
from ..models.member import Member
from marshmallow import fields

class CollectionSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Collection
        load_instance = True
        fields = ('id', 'name', 'description', 'theme', 'curator_id', 'curators', 'created_at', 'artworks')

    curator_id = fields.Integer(allow_none=True)
    curators = fields.Method("get_curators")
    artworks = fields.Method("get_artworks")
    
    def get_curators(self, obj):
        result = []
        creator = Member.query.get(obj.curator_id)
        if creator:
            result.append({"id": creator.id, "name": creator.name, "is_creator": True})

        from ..models.collection_curator import CollectionCurator
        co_curator_entries = CollectionCurator.query.filter_by(collection_id=obj.id).all()
        for entry in co_curator_entries:
            co_curator = Member.query.get(entry.member_id)
            if co_curator:
                result.append({"id": co_curator.id, "name": co_curator.name, "is_creator": False})

        return result

    def get_artworks(self, obj):
        from ..models.collection_artwork import CollectionArtwork
        from ..models.artwork import Artwork
        from .artwork import ArtworkSchema

        entries = CollectionArtwork.query.filter_by(collection_id=obj.id).all()
        artwork_ids = [e.artwork_id for e in entries]
        artworks = Artwork.query.filter(Artwork.id.in_(artwork_ids)).all()
        return ArtworkSchema(many=True).dump(artworks)
