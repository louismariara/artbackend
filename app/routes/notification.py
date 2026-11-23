from flask import Blueprint, jsonify
from ..utils.decorators import tenant_required
from ..utils.helpers import scoped_query
from ..extensions import db
from flask_jwt_extended import get_jwt_identity
from ..models.notification import Notification

notification_bp = Blueprint('notification', __name__)

@notification_bp.route("/notifications", methods=["GET"])
@tenant_required
def get_notifications():
    current_user_id = get_jwt_identity()
    notes = scoped_query(Notification).filter_by(member_id=current_user_id).order_by(Notification.created_at.desc()).all()
    return jsonify({"notifications": [
        {"id": n.id, "message": n.message, "is_read": n.is_read, "created_at": n.created_at.isoformat()}
        for n in notes
    ]})

@notification_bp.route("/notifications/<int:id>/read", methods=["PUT"])
@tenant_required
def mark_read(id):
    current_user_id = get_jwt_identity()
    note = scoped_query(Notification).filter_by(id=id, member_id=current_user_id).first()
    if not note:
        return jsonify({"message": "Notification not found"}), 404
    note.is_read = True
    db.session.commit()
    return jsonify({"message": "Marked as read"})
@notification_bp.route("/notifications/read-all", methods=["PUT"])
@tenant_required
def mark_all_read():
    current_user_id = get_jwt_identity()
    scoped_query(Notification).filter_by(member_id=current_user_id, is_read=False).update({"is_read": True})
    db.session.commit()
    return jsonify({"message": "All notifications marked as read"})