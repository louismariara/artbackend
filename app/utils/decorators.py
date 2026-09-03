from functools import wraps
from flask import jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..models.member import Member
def role_required(*allowed_roles):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            current_user_id = get_jwt_identity()
            member = Member.query.get(int(current_user_id))
            if not member:
                return jsonify({"message": "Member not found"}), 404
            if member.role.name not in allowed_roles:
                return jsonify({"message": "You do not have permission to perform this action"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator