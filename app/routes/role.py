from flask import Blueprint, jsonify, request
from ..extensions import db
from ..models.role import Role
from ..models.member import Member
from ..schemas.role import RoleSchema
from ..utils.logging import logger
from ..utils.decorators import role_required

role_bp = Blueprint('role', __name__)
role_schema = RoleSchema()

@role_bp.route("/roles", methods=["POST", "PUT"])
@role_required('admin')
def manage_role():
    data = request.get_json()
    try:
        if request.method == "POST":
            new_role = Role(name=data.get('name'))
            db.session.add(new_role)
        else:
            role = Role.query.get(data.get('id'))
            if not role:
                return jsonify({"message": "Role not found"}), 404
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
        role = Role.query.get_or_404(id)
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
        target = Member.query.get_or_404(id)
        role = Role.query.get(data.get('role_id'))
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