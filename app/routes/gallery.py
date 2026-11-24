import re
import unicodedata
from flask import Blueprint, jsonify, request

from ..extensions import limiter
from ..models.artwork import Artwork
from ..models.member import Member
from ..models.organization import Organization
from ..models.role import Role
from ..utils.email import send_inquiry_email
from ..utils.helpers import RESERVED_SUBDOMAINS, apply_lease, is_valid_slug, normalize_slug
from ..utils.notify import notify_all_admins

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

    org = apply_lease(Organization.query.filter_by(slug=slug).first())
    if org:
        payload = {"exists": True, "available": False,
                   "name": org.name, "slug": org.slug,
                   "status": org.status,
                   "logo_path": org.logo_path,
                   "background_path": org.background_path,
                   "font_heading": org.font_heading,
                   "font_body": org.font_body,
                   "currency": org.currency,
                   "color_accent": org.color_accent,
                   "color_button": org.color_button,
                   "color_heading": org.color_heading,
                   "color_bar": org.color_bar}
        if org.status != 'active':
            payload["pause_reason"] = "lease" if org.suspended_reason == "lease" else "paused"
        return jsonify(payload), 200

    if slug in RESERVED_SUBDOMAINS:
        return jsonify({"exists": False, "available": False,
                        "reason": "reserved"}), 200

    return jsonify({"exists": False, "available": True}), 200


@gallery_bp.route("/public/artworks", methods=["GET"])
@limiter.limit("60 per minute")
def public_artworks():
    """Public, no login: a gallery's most-viewed artworks, for the home page a
    visitor sees before logging in. Returns the fields a buyer needs, including
    the sale price. Storage location, condition, dimensions, view counts and
    who uploaded the piece stay private."""
    slug = normalize_slug(request.args.get('slug')) or ''
    if not is_valid_slug(slug):
        return jsonify({"message": "Gallery not found"}), 404

    org = apply_lease(Organization.query.filter_by(slug=slug).first())
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
            "price": float(a.price) if a.price is not None else None,
        }
        for a in artworks
    ]}), 200


@gallery_bp.route("/public/artworks/<int:artwork_id>", methods=["GET"])
@limiter.limit("60 per minute")
def public_artwork(artwork_id):
    """One public piece for a visitor who is not logged in. Same fields as the
    home page, including the sale price. Storage location and condition stay private."""
    slug = normalize_slug(request.args.get('slug')) or ''
    if not is_valid_slug(slug):
        return jsonify({"message": "Artwork not found"}), 404

    org = apply_lease(Organization.query.filter_by(slug=slug).first())
    if not org:
        return jsonify({"message": "Artwork not found"}), 404
    if org.status != 'active':
        return jsonify({"message": "This gallery has been suspended"}), 403

    artwork = Artwork.query.filter_by(id=artwork_id, organization_id=org.id).first()
    if not artwork:
        return jsonify({"message": "Artwork not found"}), 404

    return jsonify({"artwork": {
        "id": artwork.id,
        "title": artwork.title,
        "artist": artwork.artist,
        "medium": artwork.medium,
        "category": artwork.category,
        "description": artwork.description,
        "image_path": artwork.image_path,
        "price": float(artwork.price) if artwork.price is not None else None,
    }}), 200


_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


@gallery_bp.route("/public/artworks/<int:artwork_id>/inquire", methods=["POST"])
@limiter.limit("5 per minute")
def inquire_artwork(artwork_id):
    """A visitor asks about one work without creating an account.
    Gallery admins get an in-app notice, and an email when mail is configured."""
    slug = normalize_slug(request.args.get('slug')) or ''
    if not is_valid_slug(slug):
        return jsonify({"message": "Artwork not found"}), 404

    org = apply_lease(Organization.query.filter_by(slug=slug).first())
    if not org or org.status != 'active':
        return jsonify({"message": "Artwork not found"}), 404

    artwork = Artwork.query.filter_by(id=artwork_id, organization_id=org.id).first()
    if not artwork:
        return jsonify({"message": "Artwork not found"}), 404

    data = request.get_json(silent=True) or {}
    name = data.get('name') if isinstance(data.get('name'), str) else ''
    email = data.get('email') if isinstance(data.get('email'), str) else ''
    note = data.get('message') if isinstance(data.get('message'), str) else ''
    name, email, note = name.strip(), email.strip(), note.strip()
    if not name or len(name) > 120 or not _EMAIL_RE.match(email) or len(email) > 200 or len(note) < 10 or len(note) > 800:
        return jsonify({"message": "Enter your name, a valid email, and a question of at least 10 characters."}), 400

    admins = (Member.query
              .join(Role, Member.role_id == Role.id)
              .filter(Member.organization_id == org.id, Role.name == 'admin')
              .all())
    if not admins:
        return jsonify({"message": "This gallery cannot take questions right now."}), 400

    notice = f"Question about '{artwork.title}' from {name} ({email}): {note}"
    notify_all_admins(notice[:500], org.id)
    for admin in admins:
        send_inquiry_email(admin.email, org.name, artwork.title, name, email, note)
    return jsonify({"message": "The gallery has your question."}), 200


def _fold(value):
    """Lowercase, drop accents, and treat spaces, hyphens and punctuation alike."""
    text = unicodedata.normalize('NFKD', value or '')
    text = ''.join(ch for ch in text if not unicodedata.combining(ch))
    text = text.lower().replace('-', ' ')
    text = re.sub(r'[^a-z0-9]+', ' ', text).strip()
    return re.sub(r'\s+', ' ', text)


def _search_text(raw):
    """Accept a name, a slug, or a pasted gallery address."""
    text = (raw or '').strip()
    text = re.sub(r'^https?://', '', text, flags=re.IGNORECASE)
    if ' ' not in text and ('/' in text or ':' in text or '.' in text):
        host = text.split('/')[0]
        label = host.split(':')[0].split('.')[0]
        if label.lower() == 'www':
            parts = host.split(':')[0].split('.')
            label = parts[1] if len(parts) > 1 else label
        text = label.replace('-', ' ')
    return text


def _covers(query_folded, target_folded):
    """True when every typed word starts a different word in the gallery name."""
    query_words = query_folded.split()
    target_words = target_folded.split()
    if not query_words:
        return False
    used = [False] * len(target_words)
    for word in query_words:
        found = False
        for index, target in enumerate(target_words):
            if used[index]:
                continue
            if target.startswith(word) or (len(target) >= 3 and word.startswith(target)):
                used[index] = True
                found = True
                break
        if not found:
            return False
    return True


@gallery_bp.route("/find-gallery", methods=["GET"])
@limiter.limit("30 per minute")
def find_gallery():
    """Send a visitor to one gallery from a loosely typed name.

    A single confident match returns that gallery's address. Several matches
    return only "vague", with no names and no count, so a caller cannot
    learn that another gallery exists. No match returns "none"."""
    folded = _fold(_search_text(request.args.get('q')))
    compact = folded.replace(' ', '')
    if len(compact) < 3:
        return jsonify({"result": "vague"}), 200

    exact = []
    partial = []
    for org in Organization.query.all():
        name = _fold(org.name)
        slug = _fold(org.slug)
        if compact in (name.replace(' ', ''), slug.replace(' ', '')):
            exact.append(org)
        elif _covers(folded, name) or _covers(folded, slug):
            partial.append(org)

    chosen = exact if exact else partial
    if len(chosen) == 1:
        org = apply_lease(chosen[0])
        return jsonify({"result": "found", "slug": org.slug, "status": org.status}), 200
    if len(chosen) > 1:
        return jsonify({"result": "vague"}), 200
    return jsonify({"result": "none"}), 200


@gallery_bp.after_request
def never_cache(response):
    """Gallery status and the public artwork list must always be fresh."""
    response.headers['Cache-Control'] = 'no-store'
    return response
