"""gallery heading and body fonts

Revision ID: d7c4a91e2b08
Revises: c3a8e1b74f20
Create Date: 2026-11-24 13:20:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'd7c4a91e2b08'
down_revision = 'c3a8e1b74f20'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.add_column(sa.Column('font_heading', sa.String(length=40), nullable=True))
        batch_op.add_column(sa.Column('font_body', sa.String(length=40), nullable=True))


def downgrade():
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.drop_column('font_body')
        batch_op.drop_column('font_heading')
