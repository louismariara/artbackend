from datetime import datetime
from flask import Blueprint, jsonify, request,g
from ..extensions import db
from ..models.role import Role
from ..models.member import Member
from ..schemas.role import RoleSchema
from ..utils.logging import logger
from ..utils.decorators import role_required
from ..utils.helpers import scoped_query, scoped_get
from flask_jwt_extended import get_jwt
from ..models.session import Session
from flask_jwt_extended import get_jwt_identity


PROTECTED_ROLE_NAMES = {'admin', 'curator', 'member'}
role_bp = Blueprint('role', __name__)
role_schema = RoleSchema()

@role_bp.route("/roles", methods=["POST", "PUT"])
@role_required('admin')
def manage_role():
    data = request.get_json()
    try:
        if request.method == "POST":
            new_role = Role(organization_id=g.org_id, name=data.get('name'))
            db.session.add(new_role)
        else:
            role = scoped_get(Role, data.get('id'))
            if not role:
                return jsonify({"message": "Role not found"}), 404
            if role.name in PROTECTED_ROLE_NAMES:
                return jsonify({"message": f"Cannot rename the built-in '{role.name}' role"}), 400   
            role.name = data.get('name')
        db.session.commit()
        return jsonify({"message": f"Role {'created' if request.method == 'POST' else 'updated'} successfully", "role": role_schema.dump(role if request.method == "PUT" else new_role)})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error managing role: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500

@role_bp.route("/roles/<int:id>", methods=["DELETE"])
@role_required('admin')
def delete_role(id):
    try:
        role = scoped_get(Role, id)
        if not role:
            return jsonify({"message": "Role not found"}), 404
        if role.name in PROTECTED_ROLE_NAMES:
            return jsonify({"message": f"Cannot delete the built-in '{role.name}' role"}), 400
        if role.members:
            return jsonify({"message": "Cannot delete role; it's assigned to users"}), 400
        db.session.delete(role)
        db.session.commit()
        logger.info(f"Role deleted: {role.name}")
        return jsonify({"message": "Role deleted successfully"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting role: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500

@role_bp.route("/members/<int:id>/role", methods=["PUT"])
@role_required('admin')
def change_member_role(id):
    data = request.get_json()
    try:
        target = scoped_get(Member, id)
        if not target:
            return jsonify({"message": "Member not found"}), 404
        role = scoped_get(Role, data.get('role_id'))
        if not role:
            return jsonify({"message": "Role does not exist"}), 400
        target.role_id = role.id
        db.session.commit()
        logger.info(f"Member {target.email} role changed to {role.name}")
        return jsonify({"message": f"{target.name}'s role updated to {role.name}"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error changing role: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500

@role_bp.route("/admin/members/<int:id>/block", methods=["POST"])
@role_required('admin')
def block_member(id):
    current_user_id = get_jwt_identity()
    if str(id) == str(current_user_id):
        return jsonify({"message": "You cannot block your own account"}), 400
    try:
        target = scoped_get(Member, id)
        if not target:
            return jsonify({"message": "Member not found"}), 404
        target.admin_locked = True
        scoped_query(Session).filter_by(member_id=id, revoked=False).update({
            "revoked": True,
            "revoked_at": datetime.now(),
            "revoked_by": "admin"
        })
        db.session.commit()
        logger.info(f"Member {target.email} blocked by admin (id={id})")
        return jsonify({"message": f"{target.name} has been blocked"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error blocking member {id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@role_bp.route("/admin/members/<int:id>/unblock", methods=["POST"])
@role_required('admin')
def unblock_member(id):
    try:
        target = scoped_get(Member, id)
        if not target:
            return jsonify({"message": "Member not found"}), 404
        target.admin_locked = False
        target.failed_attempts = 0
        target.locked_until = None
        target.unlock_attempts = 0
        db.session.commit()
        logger.info(f"Member {target.email} unblocked by admin (id={id})")
        return jsonify({"message": f"{target.name} has been unblocked"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error unblocking member {id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
    
@role_bp.route("/admin/sessions", methods=["GET"])
@role_required('admin')
def list_sessions():
    try:
        current_jti = get_jwt().get('jti')
        member_id = request.args.get('member_id')
        query = scoped_query(Session).filter_by(revoked=False)
        if member_id:
            query = query.filter_by(member_id=member_id)

        sessions = query.all()
        result = []
        for s in sessions:
            member = Member.query.get(s.member_id)
            result.append({
                "id": s.id,
                "member_id": s.member_id,
                "member_name": member.name if member else "Unknown",
                "device_info": s.device_info,
                "ip_address": s.ip_address,
                "created_at": s.created_at.isoformat(),
                "is_current": s.jti == current_jti
            })
        return jsonify({"sessions": result})
    except Exception as e:
        logger.error(f"Error listing sessions: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
@role_bp.route("/admin/logout-all", methods=["POST"])
@role_required('admin')
def logout_all():
    try:
        current_sid = get_jwt().get('sid')
        sessions = scoped_query(Session).filter(Session.revoked == False, Session.jti != current_sid).all()
        for s in sessions:
            s.revoked = True
            s.revoked_at = datetime.now()
            s.revoked_by = "admin"
        db.session.commit()
        return jsonify({"message": f"{len(sessions)} session(s) revoked"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error during logout-all: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@role_bp.route("/admin/sessions/<int:id>", methods=["DELETE"])
@role_required('admin')
def revoke_session(id):
    try:
        session = scoped_get(Session, id)
        if not session or session.revoked:
            return jsonify({"message": "Session not found or already revoked"}), 404

        current_sid = get_jwt().get('sid')
        if session.jti == current_sid:
            return jsonify({"message": "You cannot revoke your own current session. Use logout instead."}), 400

        session.revoked = True
        session.revoked_at = datetime.now()
        session.revoked_by = "admin"
        db.session.commit()
        return jsonify({"message": "Session revoked"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error revoking session {id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
        
@role_bp.route("/members", methods=["GET"])
@role_required('admin')
def list_members():
    try:
        members = scoped_query(Member).all()
        result = []
        for m in members:
            result.append({
                "id": m.id,
                "name": m.name,
                "email": m.email,
                "role_id": m.role_id,
                "admin_locked": m.admin_locked,
                "locked_until": m.locked_until.isoformat() if m.locked_until else None
            })
        return jsonify({"members": result})
    except Exception as e:
        logger.error(f"Error listing members: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
@role_bp.route("/members/eligible-collaborators", methods=["GET"])
@role_required('admin', 'curator')
def list_eligible_collaborators():
    try:
        members = scoped_query(Member).filter(Role.id == Member.role_id, Role.name.in_(['admin', 'curator'])).all()
        result = [{"id": m.id, "name": m.name, "role_id": m.role_id} for m in members]
        return jsonify({"members": result})
    except Exception as e:
        logger.error(f"Error listing eligible collaborators: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
        
@role_bp.route("/roles", methods=["GET"])
@role_required('admin')
def list_roles():
    try:
        roles = scoped_query(Role).all()
        return jsonify({"roles": role_schema.dump(roles, many=True)})
    except Exception as e:
        logger.error(f"Error listing roles: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
