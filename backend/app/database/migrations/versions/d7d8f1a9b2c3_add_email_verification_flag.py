"""Add is_email_verified flag to users

Revision ID: d7d8f1a9b2c3
Revises: 1688f4a93685
Create Date: 2026-07-29 20:50:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd7d8f1a9b2c3'
down_revision: Union[str, None] = '1688f4a93685'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('is_email_verified', sa.Boolean(), nullable=True, server_default='0'))


def downgrade() -> None:
    op.drop_column('users', 'is_email_verified')
