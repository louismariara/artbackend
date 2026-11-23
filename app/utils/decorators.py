from functools import wraps
from flask import jsonify, g
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from ..models.member import Member
from ..models.super_admin import SuperAdmin


def role_required(*allowed_roles):
    def decorator(fn):
        @wraps(fn)
        @tenant_required
        def wrapper(*args, **kwargs):
            if g.current_member.role.name not in allowed_roles:
                return jsonify({"message": "You do not have permission to perform this action"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator 

def tenant_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        org_id = get_jwt().get("org_id")
        if org_id is None:
            return jsonify({"message": "No organization found on this token"}), 401

        current_user_id = get_jwt_identity()
        member = Member.query.get(int(current_user_id))
        if not member:
            return jsonify({"message": "Member not found"}), 404
        if member.organization_id != org_id:
            # Token's org claim doesn't match the member's actual gallery —
            # e.g. a stale token from before a member was moved/removed.
            return jsonify({"message": "Token does not match your account"}), 401
        if member.organization and member.organization.status != 'active':
            # Gallery suspended by a super admin — block access even on an
            # otherwise-valid, unexpired token.
            return jsonify({"message": "This gallery has been suspended"}), 403

        g.org_id = org_id
        g.current_member = member
        return fn(*args, **kwargs)
    return wrapper


def super_admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        if get_jwt().get("scope") != "platform":
            return jsonify({"message": "Platform admin access required"}), 403

        current_id = get_jwt_identity()
        super_admin = SuperAdmin.query.get(int(current_id))
        if not super_admin:
            return jsonify({"message": "Super admin not found"}), 404

        g.current_super_admin = super_admin
        return fn(*args, **kwargs)
    return wrapper