"""empty message

Revision ID: 6482a3250a82
Revises: 
Create Date: 2024-09-21 21:57:21.611750

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6482a3250a82'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('character',
    sa.Column('character_id', sa.BigInteger(), autoincrement=False, nullable=False),
    sa.Column('character_name', sa.String(length=200), nullable=True),
    sa.PrimaryKeyConstraint('character_id')
    )
    op.create_table('match',
    sa.Column('match_id', sa.Integer(), nullable=False),
    sa.Column('tournament_id', sa.Integer(), nullable=False),
    sa.Column('red_team_name', sa.String(length=255), nullable=True),
    sa.Column('red_team_members', sa.String(length=2048), nullable=True),
    sa.Column('blue_team_name', sa.String(length=255), nullable=True),
    sa.Column('blue_team_members', sa.String(length=2048), nullable=True),
    sa.ForeignKeyConstraint(['tournament_id'], ['tournament.tournament_id'], ),
    sa.PrimaryKeyConstraint('match_id')
    )
    op.create_table('tournament',
    sa.Column('tournament_id', sa.Integer(), nullable=False),
    sa.Column('tournament_name', sa.String(length=255), nullable=True),
    sa.Column('tournament_description', sa.String(length=1024), nullable=True),
    sa.Column('tournament_url', sa.String(length=255), nullable=True),
    sa.Column('tournament_type', sa.String(length=40), nullable=True),
    sa.Column('active', sa.Integer(), nullable=True),
    sa.Column('current_match_id', sa.Integer(), nullable=True),
    sa.Column('team_size', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['current_match_id'], ['match.match_id'], ),
    sa.PrimaryKeyConstraint('tournament_id')
    )
    op.create_table('user',
    sa.Column('character_id', sa.BigInteger(), autoincrement=False, nullable=False),
    sa.Column('character_owner_hash', sa.String(length=255), nullable=True),
    sa.Column('character_name', sa.String(length=200), nullable=True),
    sa.Column('access_token', sa.String(length=4096), nullable=True),
    sa.Column('access_token_expires', sa.DateTime(), nullable=True),
    sa.Column('refresh_token', sa.String(length=100), nullable=True),
    sa.PrimaryKeyConstraint('character_id')
    )
    op.create_table('player',
    sa.Column('competitor_id', sa.Integer(), nullable=False),
    sa.Column('character_id', sa.Integer(), nullable=True),
    sa.Column('tournament_id', sa.Integer(), nullable=False),
    sa.Column('active', sa.Integer(), nullable=True),
    sa.Column('wins', sa.Integer(), nullable=True),
    sa.Column('losses', sa.Integer(), nullable=True),
    sa.Column('matches', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['tournament_id'], ['tournament.tournament_id'], ),
    sa.PrimaryKeyConstraint('competitor_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('player')
    op.drop_table('user')
    op.drop_table('tournament')
    op.drop_table('match')
    op.drop_table('character')
    # ### end Alembic commands ###
