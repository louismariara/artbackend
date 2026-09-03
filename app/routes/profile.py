from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..extensions import db
from ..models.member import Member
from ..schemas.member import MemberSchema
from ..utils.logging import logger

profile_bp = Blueprint('profile', __name__)
member_schema = MemberSchema()


@profile_bp.route("/profile", methods=["GET"])
@jwt_required()
def get_profile():
    try:
        current_user_id = get_jwt_identity()
        member = Member.query.get_or_404(current_user_id)
        return jsonify({"member": member_schema.dump(member)})
    except Exception as e:
        logger.error(f"Error retrieving profile: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500

@profile_bp.route("/update-profile", methods=["PUT"])
@jwt_required()
def update_profile():
    data = request.get_json()
    try:
        current_user_id = get_jwt_identity()
        member = Member.query.get_or_404(current_user_id)
        if 'name' in data:
            member.name = data['name']
        if 'email' in data:
            if Member.query.filter(Member.id != member.id, Member.email == data['email']).first():
                return jsonify({"message": "Email already in use"}), 400
            member.email = data['email']
        db.session.commit()
        logger.info(f"User profile updated: {member.name}")
        return jsonify({"message": "Profile updated successfully", "member": member_schema.dump(member)})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating profile: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500