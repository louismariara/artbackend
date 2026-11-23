from ..extensions import db
from ..models.notification import Notification
from ..models.member import Member
from ..models.role import Role


def create_notification(member_id, message):
    # Take the gallery from the member being notified, so it's always correct
    # and doesn't depend on being inside a request.
    member = Member.query.get(member_id)
    if not member:
        return
    n = Notification(organization_id=member.organization_id, member_id=member_id, message=message)
    db.session.add(n)
    db.session.commit()


def notify_all_admins(message, organization_id=None):
    """Notify the admins of ONE gallery. With no organization_id (e.g. a rate-limit
    alarm that can't be tied to a gallery) nobody is notified — that kind of event
    belongs to the platform super admin (step 8), not to any gallery's admin."""
    if organization_id is None:
        return
    admins = (Member.query
              .join(Role, Member.role_id == Role.id)
              .filter(Member.organization_id == organization_id, Role.name == 'admin')
              .all())
    for admin in admins:
        create_notification(admin.id, message)