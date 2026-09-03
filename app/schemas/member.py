from ..extensions import ma
from ..models.member import Member

class MemberSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Member
        load_instance = True
        exclude = ("password",)