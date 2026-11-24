"""add paid_until to organization

Revision ID: b7e1c4a92d10
Revises: 8446d975beab
Create Date: 2026-11-24 11:50:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'b7e1c4a92d10'
down_revision = '8446d975beab'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.add_column(sa.Column('paid_until', sa.Date(), nullable=True))


def downgrade():
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.drop_column('paid_until')
