from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from ..extensions import db
from ..models.artwork import Artwork
from ..schemas.artwork import ArtworkSchema  # Import schema class
from ..utils.logging import logger
from datetime import datetime, timedelta

inventory_bp = Blueprint('inventory', __name__)

# Instantiate schema locally
artworks_schema = ArtworkSchema(many=True)

@inventory_bp.route("/inventory-alerts", methods=["GET"])
@jwt_required()
def check_inventory_alerts():
    try:
        six_months_ago = datetime.now() - timedelta(days=180)
        alerts = Artwork.query.filter(
            (Artwork.condition == 'poor') |
            (Artwork.updated_at < six_months_ago)
        ).all()
        return jsonify({"alerts": artworks_schema.dump(alerts)})
    except Exception as e:
        logger.error(f"Alert system down: {str(e)}")
        return jsonify({"message": f"Alert check failed: {str(e)}"}), 500