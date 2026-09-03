from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..extensions import db
from ..models.artwork import Artwork
from ..models.member import Member
from ..schemas.artwork import ArtworkSchema
from ..utils.logging import logger
from sqlalchemy import or_

artwork_bp = Blueprint('artwork', __name__)

artwork_schema = ArtworkSchema()
artworks_schema = ArtworkSchema(many=True)


def _get_current_member():
    current_user_id = get_jwt_identity()
    return Member.query.get(int(current_user_id))


def _can_modify(member, artwork):
    """Admin can modify anything. Curator can only modify their own artwork."""
    if member.role.name == 'admin':
        return True
    if member.role.name == 'curator' and artwork.member_id == member.id:
        return True
    return False


@artwork_bp.route("/artworks", methods=["GET"])
@jwt_required()
def get_artworks():
    # Open to everyone logged in — admin, curator, and member all browse
    # the same way.
    try:
        artworks = Artwork.query.all()
        return jsonify({"artworks": artworks_schema.dump(artworks)})
    except Exception as e:
        logger.error(f"Error retrieving artworks: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@artwork_bp.route("/artworks", methods=["POST"])
@jwt_required()
def create_artwork():
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"message": "Request body must be valid JSON"}), 400

    try:
        member = _get_current_member()
        if member.role.name not in ["admin", "curator"]:
            return jsonify({"message": "Only admins and curators can add artwork"}), 403

        required_fields = ['title', 'artist']
        missing = [f for f in required_fields if not data.get(f)]
        if missing:
            logger.warning(f"Create artwork failed: missing field(s) {missing}. Received: {list(data.keys())}")
            return jsonify({
                "message": f"Missing or empty field(s): {', '.join(missing)}",
                "missing_fields": missing
            }), 400

        if len(data.get('title', '')) > 200 or len(data.get('title', '')) < 3:
            return jsonify({"message": "Title must be between 3 and 200 characters"}), 400

        valid_conditions = ['good', 'fair', 'poor']
        if data.get('condition') and data.get('condition') not in valid_conditions:
            return jsonify({"message": f"Invalid condition. Must be one of: {', '.join(valid_conditions)}"}), 400

        new_artwork = Artwork(
            title=data.get('title'),
            artist=data.get('artist'),
            medium=data.get('medium'),
            dimensions=data.get('dimensions'),
            condition=data.get('condition'),
            location=data.get('location'),
            theme=data.get('theme'),
            image_path=data.get('image_path'),
            description=data.get('description'),
            member_id=member.id  # record ownership
        )
        db.session.add(new_artwork)
        db.session.commit()
        logger.info(f"New artwork added: '{new_artwork.title}' by member {member.id}")
        return jsonify({"message": "Artwork added!", "artwork": artwork_schema.dump(new_artwork)}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Artwork creation failed: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@artwork_bp.route("/artworks/<int:artwork_id>", methods=["GET"])
@jwt_required()
def get_artwork(artwork_id):
    try:
        artwork = Artwork.query.get(artwork_id)
        if not artwork:
            return jsonify({"message": "Artwork not found"}), 404
        return jsonify({"artwork": artwork_schema.dump(artwork)})
    except Exception as e:
        logger.error(f"Error retrieving artwork {artwork_id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@artwork_bp.route("/artworks/<int:id>", methods=["PUT"])
@jwt_required()
def update_artwork(id):
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"message": "Request body must be valid JSON"}), 400

    try:
        artwork = Artwork.query.get_or_404(id)
        member = _get_current_member()

        if not _can_modify(member, artwork):
            return jsonify({"message": "You can only edit artwork you uploaded"}), 403

        if 'title' in data and (len(data['title']) > 200 or len(data['title']) < 3):
            return jsonify({"message": "Title must be between 3 and 200 characters"}), 400
        if 'condition' in data and data['condition'] not in ['good', 'fair', 'poor']:
            return jsonify({"message": "Invalid condition. Must be one of: good, fair, poor"}), 400

        # Whitelist: only these fields can be updated — never id, member_id, views, etc.
        allowed_fields = ['title', 'artist', 'medium', 'dimensions', 'condition', 'location', 'theme', 'image_path', 'description']
        for key in allowed_fields:
            if key in data:
                setattr(artwork, key, data[key])

        db.session.commit()
        logger.info(f"Artwork updated: '{artwork.title}' (id={id}) by member {member.id}")
        return jsonify({"message": "Artwork updated!", "artwork": artwork_schema.dump(artwork)})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Artwork update failed for id={id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@artwork_bp.route("/artworks/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_artwork(id):
    try:
        artwork = Artwork.query.get_or_404(id)
        member = _get_current_member()

        if not _can_modify(member, artwork):
            return jsonify({"message": "You can only delete artwork you uploaded"}), 403

        title = artwork.title
        db.session.delete(artwork)
        db.session.commit()
        logger.info(f"Artwork deleted: '{title}' (id={id}) by member {member.id}")
        return jsonify({"message": "Artwork deleted!"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Artwork deletion failed for id={id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@artwork_bp.route("/featured-artworks", methods=["GET"])
@jwt_required()
def get_featured_artworks():
    try:
        featured_artworks = Artwork.query.order_by(Artwork.views.desc(), Artwork.updated_at.desc()).limit(5).all()
        return jsonify({"artworks": artworks_schema.dump(featured_artworks)})
    except Exception as e:
        logger.error(f"Error retrieving featured artworks: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@artwork_bp.route("/search-artworks", methods=["GET"])
@jwt_required()
def search_artworks():
    try:
        query = request.args.get('q', '')
        artworks = Artwork.query.filter(
            or_(
                Artwork.title.ilike(f'%{query}%'),
                Artwork.artist.ilike(f'%{query}%'),
                Artwork.theme.ilike(f'%{query}%')
            )
        ).all()
        return jsonify({"artworks": artworks_schema.dump(artworks)})
    except Exception as e:
        logger.error(f"Search failed: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500