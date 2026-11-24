"""gallery top bar color

Revision ID: g2b7d94e5f31
Revises: f1a6c83d4e20
Create Date: 2026-11-24 13:55:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'g2b7d94e5f31'
down_revision = 'f1a6c83d4e20'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.add_column(sa.Column('color_bar', sa.String(length=20), nullable=True))


def downgrade():
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.drop_column('color_bar')
