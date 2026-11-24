"""gallery appearance and lease suspension reason

Revision ID: c3a8e1b74f20
Revises: b7e1c4a92d10
Create Date: 2026-11-24 12:10:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'c3a8e1b74f20'
down_revision = 'b7e1c4a92d10'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.add_column(sa.Column('suspended_reason', sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column('logo_path', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('background_path', sa.String(length=255), nullable=True))


def downgrade():
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.drop_column('background_path')
        batch_op.drop_column('logo_path')
        batch_op.drop_column('suspended_reason')
