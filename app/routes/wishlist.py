from flask import Blueprint, jsonify, request, g
from ..extensions import db
from ..models.wishlist import Wishlist
from ..models.artwork import Artwork
from ..schemas.artwork import ArtworkSchema
from ..utils.logging import logger
from ..utils.decorators import tenant_required
from ..utils.helpers import scoped_query, scoped_get
from sqlalchemy.exc import IntegrityError

wishlist_bp = Blueprint('wishlist', __name__)
artworks_schema = ArtworkSchema(many=True)


@wishlist_bp.route("/wishlist", methods=["POST"])
@tenant_required
def add_to_wishlist():
    data = request.get_json(silent=True)
    if not data or not data.get('artwork_id'):
        return jsonify({"message": "artwork_id is required"}), 400

    try:
        member = g.current_member
        artwork = scoped_get(Artwork, data['artwork_id'])
        if not artwork:
            return jsonify({"message": "Artwork not found"}), 404

        entry = Wishlist(organization_id=member.organization_id, member_id=member.id, artwork_id=data['artwork_id'])
        db.session.add(entry)
        db.session.commit()
        logger.info(f"Member {member.id} added artwork {data['artwork_id']} to wishlist")
        return jsonify({"message": "Added to wishlist"}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({"message": "This artwork is already in your wishlist"}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding to wishlist: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@wishlist_bp.route("/wishlist", methods=["GET"])
@tenant_required
def get_wishlist():
    try:
        member = g.current_member
        entries = scoped_query(Wishlist).filter_by(member_id=member.id).all()
        artwork_ids = [e.artwork_id for e in entries]
        artworks = scoped_query(Artwork).filter(Artwork.id.in_(artwork_ids)).all() if artwork_ids else []
        return jsonify({"wishlist": artworks_schema.dump(artworks)})
    except Exception as e:
        logger.error(f"Error retrieving wishlist: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@wishlist_bp.route("/wishlist/<int:artwork_id>", methods=["DELETE"])
@tenant_required
def remove_from_wishlist(artwork_id):
    try:
        member = g.current_member
        entry = scoped_query(Wishlist).filter_by(member_id=member.id, artwork_id=artwork_id).first()
        if not entry:
            return jsonify({"message": "This artwork is not in your wishlist"}), 404

        db.session.delete(entry)
        db.session.commit()
        logger.info(f"Member {member.id} removed artwork {artwork_id} from wishlist")
        return jsonify({"message": "Removed from wishlist"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error removing from wishlist: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500