from flask import Blueprint, jsonify, request, g
from ..extensions import db
from ..utils.logging import logger
from ..utils.decorators import role_required
from ..utils.helpers import is_valid_image_path

gallery_settings_bp = Blueprint('gallery_settings', __name__)

# Fixed list. A gallery picks from these; it cannot supply its own CSS.
FONT_KEYS = frozenset({
    'classic', 'garamond', 'baskerville', 'newsreader',
    'franklin', 'source', 'outfit',
})
ACCENT_KEYS = frozenset({'terracotta', 'ink', 'forest', 'navy', 'wine'})
BUTTON_KEYS = frozenset({'charcoal', 'black', 'terracotta', 'navy', 'forest'})
HEADING_KEYS = frozenset({'charcoal', 'black', 'navy', 'forest', 'wine'})
BAR_KEYS = frozenset({'charcoal', 'white', 'cream', 'ink', 'terracotta', 'navy', 'forest', 'wine'})
# Empty currency means Kenyan shillings, the default.
CURRENCY_KEYS = frozenset({
    'ksh', 'usd', 'eur', 'gbp', 'ugx', 'tzs', 'rwf', 'zar', 'ngn', 'aed', 'inr',
})


def _appearance(org):
    return {
        "name": org.name,
        "slug": org.slug,
        "logo_path": org.logo_path,
        "background_path": org.background_path,
        "font_heading": org.font_heading,
        "font_body": org.font_body,
        "currency": org.currency,
        "color_accent": org.color_accent,
        "color_button": org.color_button,
        "color_heading": org.color_heading,
        "color_bar": org.color_bar,
    }


def _clean_font(value):
    if value in (None, ''):
        return None
    if not isinstance(value, str) or value not in FONT_KEYS:
        return 'invalid'
    return value


def _clean_choice(value, allowed):
    if value in (None, ''):
        return None
    if not isinstance(value, str) or value not in allowed:
        return 'invalid'
    return value


def _clean_path(value, org_id):
    if value in (None, ''):
        return None
    if not is_valid_image_path(value, org_id):
        return 'invalid'
    if isinstance(value, str) and value.startswith('uploads/'):
        value = value[len('uploads/'):]
    return value


@gallery_settings_bp.route("/gallery-settings", methods=["GET"])
@role_required('admin')
def get_gallery_settings():
    return jsonify({"gallery": _appearance(g.current_member.organization)}), 200


@gallery_settings_bp.route("/gallery-settings", methods=["PATCH"])
@role_required('admin')
def update_gallery_settings():
    """Display name, logo, background and typefaces. The gallery address (slug)
    stays put so existing links keep working."""
    data = request.get_json(silent=True) or {}
    org = g.current_member.organization
    try:
        if 'name' in data:
            name = data.get('name')
            if not isinstance(name, str) or not name.strip() or len(name.strip()) > 150:
                return jsonify({"message": "Gallery name must be 1-150 characters"}), 400
            org.name = name.strip()

        for field in ('logo_path', 'background_path'):
            if field not in data:
                continue
            cleaned = _clean_path(data.get(field), org.id)
            if cleaned == 'invalid':
                db.session.rollback()
                return jsonify({"message": "Upload the image first, then save it."}), 400
            setattr(org, field, cleaned)

        for field in ('font_heading', 'font_body'):
            if field not in data:
                continue
            cleaned = _clean_font(data.get(field))
            if cleaned == 'invalid':
                db.session.rollback()
                return jsonify({"message": "Choose a font from the list."}), 400
            setattr(org, field, cleaned)

        if 'currency' in data:
            cleaned = _clean_choice(data.get('currency'), CURRENCY_KEYS)
            if cleaned == 'invalid':
                db.session.rollback()
                return jsonify({"message": "Choose a currency from the list."}), 400
            org.currency = cleaned

        for field, allowed, message in (
            ('color_accent', ACCENT_KEYS, 'Choose a link color from the list.'),
            ('color_button', BUTTON_KEYS, 'Choose a button color from the list.'),
            ('color_heading', HEADING_KEYS, 'Choose a heading color from the list.'),
            ('color_bar', BAR_KEYS, 'Choose a bar color from the list.'),
        ):
            if field not in data:
                continue
            cleaned = _clean_choice(data.get(field), allowed)
            if cleaned == 'invalid':
                db.session.rollback()
                return jsonify({"message": message}), 400
            setattr(org, field, cleaned)

        db.session.commit()
        logger.info(f"Gallery appearance updated for '{org.name}' by member {g.current_member.id}")
        return jsonify({"message": "Gallery appearance saved", "gallery": _appearance(org)}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Gallery appearance update failed: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
