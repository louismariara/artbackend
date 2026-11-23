from ..extensions import ma
from ..models.member import Member


class MemberSchema(ma.SQLAlchemyAutoSchema):
    """What the frontend is allowed to see about a member. This is an allow-list:
    internal columns (lock counters, rate-limit state, OTP fields, token
    timestamps, reset tokens, password hash) are never listed, so adding a new
    column to Member later can't leak it."""

    role_name = ma.Function(lambda member: member.role.name if member.role else None)

    class Meta:
        model = Member
        load_instance = True
        include_fk = True
        fields = ("id", "name", "email", "role_id", "role_name", "organization_id")