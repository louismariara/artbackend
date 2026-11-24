from datetime import datetime
from decimal import Decimal, InvalidOperation
from flask import Blueprint, jsonify, request
from ..extensions import db
from ..models.artwork import Artwork
from ..models.member import Member
from ..models.comment import Comment
from ..models.wishlist import Wishlist
from ..models.activity_log import ActivityLog
from ..models.artwork_collaborator import ArtworkCollaborator
from ..models.collection_artwork import CollectionArtwork
from ..schemas.artwork import ArtworkSchema
from flask_jwt_extended import get_jwt_identity
from ..utils.logging import logger
from ..utils.activity import log_activity
from ..extensions import limiter
from ..utils.notify import create_notification
from ..utils.decorators import tenant_required
from ..utils.helpers import scoped_query, scoped_get, is_valid_image_path
artwork_bp = Blueprint('artwork', __name__)

artwork_schema = ArtworkSchema()
artworks_schema = ArtworkSchema(many=True)


def _get_current_member():
    current_user_id = get_jwt_identity()
    return Member.query.get(int(current_user_id))


def _clean_price(value):
    """None means the piece has no listed price. Anything else must be a
    non-negative amount with at most two decimal places."""
    if value in (None, ''):
        return None
    try:
        price = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return 'invalid'
    if not price.is_finite() or price < 0 or price.copy_abs() >= Decimal('100000000'):
        return 'invalid'
    return price.quantize(Decimal('0.01'))
def _delete_limit_key():
    current_user_id = get_jwt_identity()
    return str(current_user_id)

def _delete_limit_breach(request_limit):
    current_user_id = get_jwt_identity()
    member = Member.query.get(int(current_user_id))
    if not member:
        return
    member.ip_rate_violations += 1  # reuse the same escalation pattern
    wait_seconds = min(30 * (2 ** (member.ip_rate_violations - 1)), 5 * 60)
    if wait_seconds >= 5 * 60:
        member.tokens_valid_after = datetime.now()
        logger.warning(f"Delete-endpoint rate limit maxed for {member.email} — tokens invalidated")
    db.session.commit()


def _can_modify(member, artwork):
    """Admin can modify anything. Curator can modify their own artwork,
    or any artwork they've been added to as a collaborator."""
    if member.role.name == 'admin':
        return True
    if member.role.name != 'curator':
        return False
    if artwork.member_id == member.id:
        return True

    from ..models.artwork_collaborator import ArtworkCollaborator
    is_collaborator = ArtworkCollaborator.query.filter_by(
        artwork_id=artwork.id, member_id=member.id
    ).first()
    return is_collaborator is not None


@artwork_bp.route("/artworks", methods=["GET"])
@tenant_required
def get_artworks():
    # Open to everyone logged in — admin, curator, and member all browse
    # the same way.
    try:
        artworks = scoped_query(Artwork).all()
        return jsonify({"artworks": artworks_schema.dump(artworks)})
    except Exception as e:
        logger.error(f"Error retrieving artworks: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@artwork_bp.route("/artworks", methods=["POST"])
@tenant_required
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
        if not is_valid_image_path(data.get('image_path'), member.organization_id):
            return jsonify({"message": "Invalid image_path. Upload the image first and use the filename it returns."}), 400

        price = _clean_price(data.get('price'))
        if price == 'invalid':
            return jsonify({"message": "Price must be a number that is zero or more, with up to two decimal places."}), 400

        new_artwork = Artwork(
            organization_id=member.organization_id,
            title=data.get('title'),
            artist=data.get('artist'),
            medium=data.get('medium'),
            dimensions=data.get('dimensions'),
            condition=data.get('condition'),
            location=data.get('location'),
            theme=data.get('theme'),
            price=price,
            category=data.get('category'),
            image_path=data.get('image_path'),
            description=data.get('description'),
            member_id=member.id
        )
        db.session.add(new_artwork)
        db.session.commit()
        log_activity(new_artwork.id, member.id, "created artwork")
        logger.info(f"New artwork added: '{new_artwork.title}' by member {member.id}")
        return jsonify({"message": "Artwork added!", "artwork": artwork_schema.dump(new_artwork)}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Artwork creation failed: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
@artwork_bp.route("/artworks/<int:artwork_id>", methods=["GET"])
@tenant_required
def get_artwork(artwork_id):
    try:
        artwork = scoped_get(Artwork, artwork_id)
        if not artwork:
            return jsonify({"message": "Artwork not found"}), 404
        return jsonify({"artwork": artwork_schema.dump(artwork)})
    except Exception as e:
        logger.error(f"Error retrieving artwork {artwork_id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
    
    
@artwork_bp.route("/artworks/<int:id>", methods=["PUT"])
@tenant_required
def update_artwork(id):
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"message": "Request body must be valid JSON"}), 400

    try:
        artwork = scoped_get(Artwork, id)
        if not artwork:
            return jsonify({"message": "Artwork not found"}), 404

        member = _get_current_member()

        if not _can_modify(member, artwork):
            return jsonify({"message": "You can only edit artwork you uploaded"}), 403

        if 'title' in data and (not isinstance(data['title'], str) or len(data['title']) > 200 or len(data['title']) < 3):
            return jsonify({"message": "Title must be between 3 and 200 characters"}), 400
        # Same rule as adding an artwork: condition may be left empty, but if set it must be valid.
        if data.get('condition') and data['condition'] not in ['good', 'fair', 'poor']:
            return jsonify({"message": "Invalid condition. Must be one of: good, fair, poor"}), 400
        if 'image_path' in data and not is_valid_image_path(data['image_path'], member.organization_id):
            return jsonify({"message": "Invalid image_path. Upload the image first and use the filename it returns."}), 400

        if 'price' in data:
            price = _clean_price(data.get('price'))
            if price == 'invalid':
                return jsonify({"message": "Price must be a number that is zero or more, with up to two decimal places."}), 400
            data = {**data, 'price': price}

        allowed_fields = ['title', 'artist', 'medium', 'dimensions', 'condition', 'location', 'theme', 'image_path', 'description', 'price', 'category']
        allowed_fields_changed = [key for key in allowed_fields if key in data]
        for key in allowed_fields_changed:
            setattr(artwork, key, data[key])
        db.session.commit()
        log_activity(artwork.id, member.id, f"updated fields: {', '.join(allowed_fields_changed)}")
        logger.info(f"Artwork updated: '{artwork.title}' (id={id}) by member {member.id}")
        return jsonify({"message": "Artwork updated!", "artwork": artwork_schema.dump(artwork)})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Artwork update failed for id={id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500

@artwork_bp.route("/artworks/<int:id>/activity", methods=["GET"])
@tenant_required
def get_artwork_activity(id):
    try:
        artwork = scoped_get(Artwork, id)
        if not artwork:
            return jsonify({"message": "Artwork not found"}), 404

        member = _get_current_member()

        if not (member.role.name == 'admin' or artwork.member_id == member.id):
            return jsonify({"message": "You do not have permission to view this artwork's activity log"}), 403

        entries = ActivityLog.query.filter_by(artwork_id=id).order_by(ActivityLog.timestamp.desc()).all()
        result = []
        for entry in entries:
            actor = Member.query.get(entry.member_id)
            result.append({
                "member_id": entry.member_id,
                "member_name": actor.name if actor else "Unknown",
                "action": entry.action,
                "timestamp": entry.timestamp.isoformat()
            })
        return jsonify({"activity": result})
    except Exception as e:
        logger.error(f"Error retrieving activity log for artwork {id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@artwork_bp.route("/artworks/<int:id>", methods=["DELETE"])
@tenant_required
@limiter.limit("20 per minute", key_func=_delete_limit_key, on_breach=_delete_limit_breach)
def delete_artwork(id):
    try:
        artwork = scoped_get(Artwork, id)
        if not artwork:
            return jsonify({"message": "Artwork not found"}), 404
        member = _get_current_member()

        can_delete = member.role.name == 'admin' or artwork.member_id == member.id
        if not can_delete:
            return jsonify({"message": "You can only delete artwork you uploaded"}), 403

        title = artwork.title
        Comment.query.filter_by(artwork_id=id).delete()
        Wishlist.query.filter_by(artwork_id=id).delete()
        ActivityLog.query.filter_by(artwork_id=id).delete()
        ArtworkCollaborator.query.filter_by(artwork_id=id).delete()
        CollectionArtwork.query.filter_by(artwork_id=id).delete()
        db.session.delete(artwork)
        db.session.commit()
        logger.info(f"Artwork deleted: '{title}' (id={id}) by member {member.id}")
        return jsonify({"message": "Artwork deleted!"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Artwork deletion failed for id={id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@artwork_bp.route("/featured-artworks", methods=["GET"])
@tenant_required
def get_featured_artworks():
    try:
        featured_artworks = scoped_query(Artwork).order_by(Artwork.views.desc(), Artwork.updated_at.desc()).limit(5).all()
        return jsonify({"artworks": artworks_schema.dump(featured_artworks)})
    except Exception as e:
        logger.error(f"Error retrieving featured artworks: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500

@artwork_bp.route("/search-artworks", methods=["GET"])
@tenant_required
def search_artworks():
    try:
        name = request.args.get('name', '')
        artist = request.args.get('artist', '')
        category = request.args.get('category', '')
        theme = request.args.get('theme', '')

        query = scoped_query(Artwork)
        if name:
            query = query.filter(Artwork.title.ilike(f'%{name}%'))
        if artist:
            query = query.filter(Artwork.artist.ilike(f'%{artist}%'))
        if category:
            query = query.filter(Artwork.category.ilike(f'%{category}%'))
        if theme:
            query = query.filter(Artwork.theme.ilike(f'%{theme}%'))

        artworks = query.all()
        return jsonify({"artworks": artworks_schema.dump(artworks)})
    except Exception as e:
        logger.error(f"Search failed: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
    
    
@artwork_bp.route("/artworks/<int:id>/collaborators", methods=["POST"])
@tenant_required
def add_collaborator(id):
    data = request.get_json(silent=True)
    if not data or not data.get('member_id'):
        return jsonify({"message": "member_id is required"}), 400

    try:
        artwork = scoped_get(Artwork, id)
        if not artwork:
            return jsonify({"message": "Artwork not found"}), 404

        member = _get_current_member()

        if not (member.role.name == 'admin' or artwork.member_id == member.id):
            return jsonify({"message": "Only the artwork owner or an admin can add collaborators"}), 403

        target = scoped_query(Member).filter_by(id=data['member_id']).first()
        if not target:
            return jsonify({"message": "Member not found"}), 404

        if target.role.name not in ['curator', 'admin']:
            return jsonify({"message": "Only curators or admins can be added as collaborators"}), 400

        if target.id == artwork.member_id:
            return jsonify({"message": "This member already owns this artwork"}), 400

        existing = ArtworkCollaborator.query.filter_by(artwork_id=id, member_id=target.id).first()
        if existing:
            return jsonify({"message": "This member is already a collaborator"}), 400

        collab = ArtworkCollaborator(organization_id=member.organization_id, artwork_id=id, member_id=target.id)
        db.session.add(collab)
        db.session.commit()
        log_activity(id, member.id, f"added {target.name} as a collaborator")
        create_notification(target.id, f"{member.name} added you as a collaborator on '{artwork.title}'")
        logger.info(f"Member {target.id} added as collaborator on artwork {id} by member {member.id}")
        return jsonify({"message": f"{target.name} added as a collaborator"}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding collaborator on artwork {id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@artwork_bp.route("/artworks/<int:id>/collaborators/<int:member_id>", methods=["DELETE"])
@tenant_required
@limiter.limit("20 per minute", key_func=_delete_limit_key, on_breach=_delete_limit_breach)
def remove_collaborator(id, member_id):
    try:
        artwork = scoped_get(Artwork, id)
        if not artwork:
            return jsonify({"message": "Artwork not found"}), 404
        requester = _get_current_member()

        is_owner_or_admin = requester.role.name == 'admin' or artwork.member_id == requester.id
        is_removing_self = requester.id == member_id

        if not (is_owner_or_admin or is_removing_self):
            return jsonify({"message": "You can only remove yourself, or you must be the owner/admin"}), 403

        entry = ArtworkCollaborator.query.filter_by(artwork_id=id, member_id=member_id).first()
        if not entry:
            return jsonify({"message": "This member is not a collaborator on this artwork"}), 404

        target = Member.query.get(member_id)
        db.session.delete(entry)
        db.session.commit()
        log_activity(id, requester.id, f"removed {target.name if target else member_id} as a collaborator")
        logger.info(f"Member {member_id} removed as collaborator on artwork {id} by member {requester.id}")
        return jsonify({"message": "Collaborator removed"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error removing collaborator on artwork {id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500

@artwork_bp.route("/artworks/<int:id>/collaborators", methods=["GET"])
@tenant_required
def get_collaborators(id):
    try:
        artwork = scoped_get(Artwork, id)
        if not artwork:
            return jsonify({"message": "Artwork not found"}), 404

        entries = ArtworkCollaborator.query.filter_by(artwork_id=id).all()
        result = []
        for entry in entries:
            member = Member.query.get(entry.member_id)
            result.append({
                "member_id": entry.member_id,
                "name": member.name if member else "Unknown",
                "email": member.email if member else None,
                "added_at": entry.added_at.isoformat() if entry.added_at else None
            })
        return jsonify({"collaborators": result})
    except Exception as e:
        logger.error(f"Error listing collaborators on artwork {id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
        
@artwork_bp.route("/my-artworks", methods=["GET"])
@tenant_required
def get_my_artworks():
    try:
        current_user_id = get_jwt_identity()
        artwork_schema_single = ArtworkSchema()

        owned = scoped_query(Artwork).filter_by(member_id=current_user_id).all()

        collab_entries = ArtworkCollaborator.query.filter_by(member_id=current_user_id).all()
        collab_ids = [e.artwork_id for e in collab_entries]
        collaborated = scoped_query(Artwork).filter(Artwork.id.in_(collab_ids)).all() if collab_ids else []

        result = []
        for a in owned:
            item = artwork_schema_single.dump(a)
            item['my_role'] = 'owner'
            result.append(item)
        for a in collaborated:
            item = artwork_schema_single.dump(a)
            item['my_role'] = 'collaborator'
            result.append(item)

        return jsonify({"artworks": result})
    except Exception as e:
        logger.error(f"Error fetching my artworks for member {current_user_id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500