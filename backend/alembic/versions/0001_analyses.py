"""create analyses table

Revision ID: 0001_analyses
Revises:
Create Date: 2026-09-15

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0001_analyses"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analyses",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("indicator", sa.String(length=2048), nullable=False),
        sa.Column("indicator_type", sa.String(length=16), nullable=False),
        sa.Column("meaningful_name", sa.String(length=512), nullable=True),
        sa.Column("malicious_count", sa.Integer(), nullable=False),
        sa.Column("suspicious_count", sa.Integer(), nullable=False),
        sa.Column("threat_score", sa.Integer(), nullable=True),
        sa.Column("threat_level", sa.String(length=16), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("analyzed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_analyses_analyzed_at", "analyses", ["analyzed_at"])
    op.create_index("ix_analyses_indicator", "analyses", ["indicator"])
    op.create_index("ix_analyses_indicator_type", "analyses", ["indicator_type"])


def downgrade() -> None:
    op.drop_index("ix_analyses_indicator_type", table_name="analyses")
    op.drop_index("ix_analyses_indicator", table_name="analyses")
    op.drop_index("ix_analyses_analyzed_at", table_name="analyses")
    op.drop_table("analyses")