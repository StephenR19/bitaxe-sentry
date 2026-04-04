"""Add mac_address column to miner table

Revision ID: 003_add_mac_address
Revises: 002_add_response_time
Create Date: 2026-04-04 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = '003_add_mac_address'
down_revision = '002_add_response_time'
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    
    if 'miner' in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('miner')]
        
        if 'mac_address' not in columns:
            op.add_column('miner', sa.Column('mac_address', sa.String(), nullable=True, server_default=sa.text('NULL')))


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    
    if 'miner' in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('miner')]
        
        if 'mac_address' in columns:
            op.drop_column('miner', 'mac_address')
