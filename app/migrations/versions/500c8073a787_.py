"""empty message

Revision ID: 500c8073a787
Revises: 18fa1352a1be
Create Date: 2021-12-01 10:09:09.265583

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '500c8073a787'
down_revision = '18fa1352a1be'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('documentsurl', sa.Column('name', sa.VARCHAR(length=100), nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('documentsurl', 'name')
    # ### end Alembic commands ###
