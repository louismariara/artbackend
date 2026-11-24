"""gallery accent, button and heading colors

Revision ID: f1a6c83d4e20
Revises: e8d5b02f3c19
Create Date: 2026-11-24 13:45:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'f1a6c83d4e20'
down_revision = 'e8d5b02f3c19'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.add_column(sa.Column('color_accent', sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column('color_button', sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column('color_heading', sa.String(length=20), nullable=True))


def downgrade():
    with op.batch_alter_table('organization', schema=None) as batch_op:
        batch_op.drop_column('color_heading')
        batch_op.drop_column('color_button')
        batch_op.drop_column('color_accent')
