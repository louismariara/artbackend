from flask import Blueprint, jsonify,g
from ..models.artwork import Artwork
from ..schemas.artwork import ArtworkSchema
from ..utils.logging import logger
from ..utils.decorators import role_required
from ..utils.helpers import scoped_query
from datetime import datetime, timedelta

inventory_bp = Blueprint('inventory', __name__)

artworks_schema = ArtworkSchema(many=True)

@inventory_bp.route("/inventory-alerts", methods=["GET"])
@role_required('admin', 'curator')
def check_inventory_alerts():
    try:
        current_member = g.current_member

        six_months_ago = datetime.now() - timedelta(days=180)
        query = scoped_query(Artwork).filter(
            (Artwork.condition == 'poor') |
            (Artwork.updated_at < six_months_ago)
        )

        # Admin sees every artwork system-wide; a curator only sees alerts
        # for artwork they actually own, same scoping used everywhere else.
        if current_member.role.name != 'admin':
            query = query.filter(Artwork.member_id == current_member.id)

        alerts = query.all()
        return jsonify({"alerts": artworks_schema.dump(alerts)})
    except Exception as e:
        logger.error(f"Inventory alert check failed: {str(e)}")
        return jsonify({"message": "An error occurred"}), 500
