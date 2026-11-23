from ..extensions import db
from ..models.activity_log import ActivityLog
from ..models.artwork import Artwork

def log_activity(artwork_id, member_id, action):
    artwork = Artwork.query.get(artwork_id)
    entry = ActivityLog(
        organization_id=artwork.organization_id if artwork else None,
        artwork_id=artwork_id,
        member_id=member_id,
        action=action
    )
    db.session.add(entry)
    db.session.commit()