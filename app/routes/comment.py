from flask import Blueprint, jsonify, request, g
from ..extensions import db
from ..models.artwork import Artwork
from ..models.member import Member
from ..models.comment import Comment
from ..utils.logging import logger
from ..utils.decorators import tenant_required
from ..utils.helpers import scoped_query, scoped_get

comment_bp = Blueprint('comment', __name__)


def _can_comment(member, artwork):
    # Same rule as viewing the activity log: owner or admin, for now.
    # Will extend to include collaborators once that feature exists.
    return member.role.name == 'admin' or artwork.member_id == member.id


@comment_bp.route("/artworks/<int:id>/comments", methods=["POST"])
@tenant_required
def add_comment(id):
    data = request.get_json(silent=True)
    if not data or not data.get('content'):
        return jsonify({"message": "Comment content is required"}), 400

    try:
        artwork = scoped_get(Artwork, id)
        if not artwork:
            return jsonify({"message": "Artwork not found"}), 404
        member = g.current_member

        if not _can_comment(member, artwork):
            return jsonify({"message": "You do not have permission to comment on this artwork"}), 403

        new_comment = Comment(organization_id=member.organization_id, artwork_id=id, member_id=member.id, content=data['content'])
        db.session.add(new_comment)
        db.session.commit()
        logger.info(f"Comment added on artwork {id} by member {member.id}")
        return jsonify({"message": "Comment added"}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding comment on artwork {id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@comment_bp.route("/artworks/<int:id>/comments", methods=["GET"])
@tenant_required
def get_comments(id):
    try:
        artwork = scoped_get(Artwork, id)
        if not artwork:
            return jsonify({"message": "Artwork not found"}), 404
        member = g.current_member

        if not _can_comment(member, artwork):
            return jsonify({"message": "You do not have permission to view comments on this artwork"}), 403

        comments = scoped_query(Comment).filter_by(artwork_id=id).order_by(Comment.created_at.desc()).all()
        result = []
        for c in comments:
            author = Member.query.get(c.member_id)
            result.append({
                "id": c.id,
                "member_id": c.member_id,
                "member_name": author.name if author else "Unknown",
                "content": c.content,
                "created_at": c.created_at.isoformat()
            })
        return jsonify({"comments": result})
    except Exception as e:
        logger.error(f"Error retrieving comments for artwork {id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500