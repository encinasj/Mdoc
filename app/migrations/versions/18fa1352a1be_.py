"""empty message

Revision ID: 18fa1352a1be
Revises: 7e1112c1945f
Create Date: 2021-12-01 10:04:41.875106

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '18fa1352a1be'
down_revision = '7e1112c1945f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('documentsurl',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('url', sa.VARCHAR(length=100), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('documentsurl')
    # ### end Alembic commands ###
