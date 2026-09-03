from ..extensions import db
from ..models.role import Role
from ..utils.logging import logger

def initialize_roles(db_session):
    role_admin = Role.query.filter_by(name='admin').first()
    role_curator = Role.query.filter_by(name='curator').first()
    role_member = Role.query.filter_by(name='member').first()

    if not role_admin:
        role_admin = Role(name='admin')
        db_session.session.add(role_admin)
        logger.info("Created admin role")

    if not role_curator:
        role_curator = Role(name='curator')
        db_session.session.add(role_curator)
        logger.info("Created curator role")

    if not role_member:
        role_member = Role(name='member')
        db_session.session.add(role_member)
        logger.info("Created member role")

    db_session.session.commit()