"""gallery display currency

Revision ID: e8d5b02f3c19
Revises: d7c4a91e2b08
Create Date: 2026-11-24 13:35:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'e8d5b02f3c19'
down_revision = 'd7c4a91e2b08'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.add_column(sa.Column('currency', sa.String(length=10), nullable=True))


def downgrade():
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.drop_column('currency')
