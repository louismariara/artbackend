from flask import Blueprint, jsonify, request

from ..extensions import limiter
from ..models.artwork import Artwork
from ..models.organization import Organization
from ..utils.helpers import RESERVED_SUBDOMAINS, is_valid_slug, normalize_slug

gallery_bp = Blueprint('gallery', __name__)

PUBLIC_ARTWORK_LIMIT = 12


@gallery_bp.route("/gallery-info", methods=["GET"])
@limiter.limit("60 per minute")
def gallery_info():
    """Public, no login. Lets the frontend ask about a gallery address before
    anyone logs in or signs up. Returns only what is already public on the
    gallery's own web address: whether it exists, its display name, and
    whether it is suspended. For an address that doesn't exist it also says
    whether the address could be claimed (used by the create-a-gallery form)."""
    slug = normalize_slug(request.args.get('slug')) or ''

    if not is_valid_slug(slug):
        return jsonify({"exists": False, "available": False,
                        "reason": "invalid"}), 200

    org = Organization.query.filter_by(slug=slug).first()
    if org:
        return jsonify({"exists": True, "available": False,
                        "name": org.name, "slug": org.slug,
                        "status": org.status}), 200

    if slug in RESERVED_SUBDOMAINS:
        return jsonify({"exists": False, "available": False,
                        "reason": "reserved"}), 200

    return jsonify({"exists": False, "available": True}), 200


@gallery_bp.route("/public/artworks", methods=["GET"])
@limiter.limit("60 per minute")
def public_artworks():
    """Public, no login: a gallery's most-viewed artworks, for the home page a
    visitor sees before logging in. Deliberately returns only display fields —
    never price, storage location, condition, dimensions, view counts or who
    uploaded the piece."""
    slug = normalize_slug(request.args.get('slug')) or ''
    if not is_valid_slug(slug):
        return jsonify({"message": "Gallery not found"}), 404

    org = Organization.query.filter_by(slug=slug).first()
    if not org:
        return jsonify({"message": "Gallery not found"}), 404
    if org.status != 'active':
        return jsonify({"message": "This gallery has been suspended"}), 403

    artworks = (Artwork.query.filter_by(organization_id=org.id)
                .order_by(Artwork.views.desc(), Artwork.updated_at.desc())
                .limit(PUBLIC_ARTWORK_LIMIT).all())

    return jsonify({"artworks": [
        {
            "id": a.id,
            "title": a.title,
            "artist": a.artist,
            "medium": a.medium,
            "category": a.category,
            "description": a.description,
            "image_path": a.image_path,
        }
        for a in artworks
    ]}), 200
    
    

@gallery_bp.after_request
def never_cache(response):
    """Gallery status and the public artwork list must always be fresh."""
    response.headers['Cache-Control'] = 'no-store'
    return response
