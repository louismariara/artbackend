from flask import Blueprint, jsonify, request,g
from ..extensions import db
from ..models.member import Member
from ..schemas.member import MemberSchema
from ..utils.logging import logger
from ..utils.decorators import tenant_required

profile_bp = Blueprint('profile', __name__)
member_schema = MemberSchema()


@profile_bp.route("/profile", methods=["GET"])
@tenant_required
def get_profile():
    try:
        member = g.current_member
        return jsonify({"member": member_schema.dump(member)})
    except Exception as e:
        logger.error(f"Error retrieving profile: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500

@profile_bp.route("/update-profile", methods=["PUT"])
@tenant_required
def update_profile():
    data = request.get_json()
    try:
        member = g.current_member
        if 'name' in data:
            member.name = data['name']
        if 'email' in data:
            if Member.query.filter(Member.id != member.id, Member.organization_id == member.organization_id, Member.email == data['email']).first():
                return jsonify({"message": "Email already in use"}), 400
            member.email = data['email']
        db.session.commit()
        logger.info(f"User profile updated: {member.name}")
        return jsonify({"message": "Profile updated successfully", "member": member_schema.dump(member)})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating profile: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500