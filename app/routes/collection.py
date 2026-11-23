from flask import Blueprint, jsonify, request, g
from flask_jwt_extended import get_jwt_identity
from ..extensions import db
from ..models.collection import Collection
from ..models.member import Member
from ..models.collection_artwork import CollectionArtwork
from ..models.collection_curator import CollectionCurator
from ..schemas.collection import CollectionSchema
from ..utils.logging import logger
from ..utils.decorators import tenant_required
from ..utils.helpers import scoped_query, scoped_get
from ..extensions import limiter
from datetime import datetime
from ..utils.notify import create_notification

collection_bp = Blueprint('collection', __name__)

collection_schema = CollectionSchema()
collections_schema = CollectionSchema(many=True)


def _delete_limit_key():
    current_user_id = get_jwt_identity()
    return str(current_user_id)

def _delete_limit_breach(request_limit):
    current_user_id = get_jwt_identity()
    member = Member.query.get(int(current_user_id))
    if not member:
        return
    member.ip_rate_violations += 1
    wait_seconds = min(30 * (2 ** (member.ip_rate_violations - 1)), 5 * 60)
    if wait_seconds >= 5 * 60:
        member.tokens_valid_after = datetime.now()
        logger.warning(f"Delete-endpoint rate limit maxed for {member.email} — tokens invalidated")
    db.session.commit()


def _can_manage_collection(member, collection):
    """Admin can manage anything. The creator can manage their own collection,
    or any collection they've been added to as a co-curator."""
    if member.role.name == 'admin':
        return True
    if collection.curator_id == member.id:
        return True

    from ..models.collection_curator import CollectionCurator
    is_co_curator = CollectionCurator.query.filter_by(
        collection_id=collection.id, member_id=member.id
    ).first()
    return is_co_curator is not None


@collection_bp.route("/collections", methods=["GET"])
@tenant_required
def get_collections():
    # Open to everyone logged in — admin, curator, and member all browse the same way.
    try:
        collections = scoped_query(Collection).all()
        return jsonify({"collections": collections_schema.dump(collections)})
    except Exception as e:
        logger.error(f"Error retrieving collections: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@collection_bp.route("/collections/<int:id>", methods=["GET"])
@tenant_required
def get_collection(id):
    try:
        collection = scoped_get(Collection, id)
        if not collection:
            return jsonify({"message": "Collection not found"}), 404
        return jsonify({"collection": collection_schema.dump(collection)})
    except Exception as e:
        logger.error(f"Error retrieving collection {id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@collection_bp.route("/collections", methods=["POST"])
@tenant_required
def create_collection():
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"message": "Request body must be valid JSON"}), 400

    try:
        member = g.current_member
        if member.role.name not in ["admin", "curator"]:
            return jsonify({"message": "Only admins and curators can create collections"}), 403

        if not data.get('name'):
            return jsonify({"message": "name is required"}), 400

        new_collection = Collection(
            organization_id=member.organization_id,
            name=data.get('name'),
            description=data.get('description'),
            theme=data.get('theme'),
            curator_id=member.id
        )
        db.session.add(new_collection)
        db.session.commit()
        logger.info(f"New collection created: '{new_collection.name}' by member {member.id}")
        return jsonify({"message": "Collection created!", "collection": collection_schema.dump(new_collection)}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Collection creation failed: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@collection_bp.route("/collections/<int:id>", methods=["PUT"])
@tenant_required
def update_collection(id):
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"message": "Request body must be valid JSON"}), 400

    try:
        collection = scoped_get(Collection, id)
        if not collection:
            return jsonify({"message": "Collection not found"}), 404
        member = g.current_member

        if not _can_manage_collection(member, collection):
            return jsonify({"message": "You can only edit collections you created"}), 403

        allowed_fields = ['name', 'description', 'theme']
        for key in allowed_fields:
            if key in data:
                setattr(collection, key, data[key])

        db.session.commit()
        logger.info(f"Collection updated: '{collection.name}' (id={id}) by member {member.id}")
        return jsonify({"message": "Collection updated!", "collection": collection_schema.dump(collection)})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Collection update failed for id={id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@collection_bp.route("/collections/<int:id>", methods=["DELETE"])
@tenant_required
@limiter.limit("20 per minute", key_func=_delete_limit_key, on_breach=_delete_limit_breach)
def delete_collection(id):
    try:
        collection = scoped_get(Collection, id)
        if not collection:
            return jsonify({"message": "Collection not found"}), 404
        member = g.current_member

        if not (member.role.name == 'admin' or collection.curator_id == member.id):
            return jsonify({"message": "You can only delete collections you created"}), 403

        name = collection.name
        # Remove the rows that point at this collection first. SQLite lets you
        # skip this; Postgres refuses to delete a collection that still has them.
        CollectionArtwork.query.filter_by(collection_id=id).delete()
        CollectionCurator.query.filter_by(collection_id=id).delete()
        db.session.delete(collection)
        db.session.commit()
        logger.info(f"Collection deleted: '{name}' (id={id}) by member {member.id}")
        return jsonify({"message": "Collection deleted!"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Collection deletion failed for id={id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500

@collection_bp.route("/collections/<int:id>/artworks", methods=["POST"])
@tenant_required
def add_artwork_to_collection(id):
    data = request.get_json(silent=True)
    if not data or not data.get('artwork_id'):
        return jsonify({"message": "artwork_id is required"}), 400

    try:
        collection = scoped_get(Collection, id)
        if not collection:
            return jsonify({"message": "Collection not found"}), 404
        member = g.current_member

        if not _can_manage_collection(member, collection):
            return jsonify({"message": "You can only add artwork to collections you created"}), 403

        from ..models.artwork import Artwork
        artwork = scoped_get(Artwork, data['artwork_id'])
        if not artwork:
            return jsonify({"message": "Artwork not found"}), 404

        from ..models.collection_artwork import CollectionArtwork
        existing = CollectionArtwork.query.filter_by(collection_id=id, artwork_id=artwork.id).first()
        if existing:
            return jsonify({"message": "This artwork is already in this collection"}), 400
        entry = CollectionArtwork(organization_id=member.organization_id, collection_id=id, artwork_id=artwork.id)
        db.session.add(entry)
        db.session.commit()
        if artwork.member_id and artwork.member_id != member.id:
            create_notification(
                artwork.member_id,
                f"{member.name} added your artwork '{artwork.title}' to their collection '{collection.name}'"
            )
        logger.info(f"Artwork {artwork.id} added to collection {id} by member {member.id}")
        return jsonify({"message": "Artwork added to collection"}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding artwork to collection {id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@collection_bp.route("/collections/<int:id>/artworks/<int:artwork_id>", methods=["DELETE"])
@tenant_required
def remove_artwork_from_collection(id, artwork_id):
    try:
        collection = scoped_get(Collection, id)
        if not collection:
            return jsonify({"message": "Collection not found"}), 404
        member = g.current_member

        if not _can_manage_collection(member, collection):
            return jsonify({"message": "You can only remove artwork from collections you created"}), 403

        from ..models.collection_artwork import CollectionArtwork
        entry = CollectionArtwork.query.filter_by(collection_id=id, artwork_id=artwork_id).first()
        if not entry:
            return jsonify({"message": "This artwork is not in this collection"}), 404

        db.session.delete(entry)
        db.session.commit()
        logger.info(f"Artwork {artwork_id} removed from collection {id} by member {member.id}")
        return jsonify({"message": "Artwork removed from collection"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error removing artwork from collection {id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
    
@collection_bp.route("/collections/<int:id>/curators", methods=["POST"])
@tenant_required
def add_co_curator(id):
    data = request.get_json(silent=True)
    if not data or not data.get('member_id'):
        return jsonify({"message": "member_id is required"}), 400

    try:
        collection = scoped_get(Collection, id)
        if not collection:
            return jsonify({"message": "Collection not found"}), 404
        member = g.current_member

        if not (member.role.name == 'admin' or collection.curator_id == member.id):
            return jsonify({"message": "Only the collection's creator or an admin can add co-curators"}), 403

        target = scoped_get(Member, data['member_id'])
        if not target:
            return jsonify({"message": "Member not found"}), 404

        if target.role.name not in ['curator', 'admin']:
            return jsonify({"message": "Only curators or admins can be added as co-curators"}), 400

        if target.id == collection.curator_id:
            return jsonify({"message": "This member already created this collection"}), 400

        from ..models.collection_curator import CollectionCurator
        existing = CollectionCurator.query.filter_by(collection_id=id, member_id=target.id).first()
        if existing:
            return jsonify({"message": "This member is already a co-curator"}), 400

        entry = CollectionCurator(organization_id=member.organization_id, collection_id=id, member_id=target.id)
        db.session.add(entry)
        db.session.commit()
        create_notification(target.id, f"{member.name} added you as a co-curator on the collection '{collection.name}'")
        logger.info(f"Member {target.id} added as co-curator on collection {id} by member {member.id}")
        return jsonify({"message": f"{target.name} added as a co-curator"}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding co-curator on collection {id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500


@collection_bp.route("/collections/<int:id>/curators/<int:member_id>", methods=["DELETE"])
@tenant_required
@limiter.limit("20 per minute", key_func=_delete_limit_key, on_breach=_delete_limit_breach)
def remove_co_curator(id, member_id):
    try:
        collection = scoped_get(Collection, id)
        if not collection:
            return jsonify({"message": "Collection not found"}), 404
        requester = g.current_member

        is_owner_or_admin = requester.role.name == 'admin' or collection.curator_id == requester.id
        is_removing_self = requester.id == member_id

        if not (is_owner_or_admin or is_removing_self):
            return jsonify({"message": "You can only remove yourself, or you must be the creator/admin"}), 403

        from ..models.collection_curator import CollectionCurator
        entry = CollectionCurator.query.filter_by(collection_id=id, member_id=member_id).first()
        if not entry:
            return jsonify({"message": "This member is not a co-curator on this collection"}), 404

        db.session.delete(entry)
        db.session.commit()
        logger.info(f"Member {member_id} removed as co-curator on collection {id} by member {requester.id}")
        return jsonify({"message": "Co-curator removed"})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error removing co-curator on collection {id}: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500