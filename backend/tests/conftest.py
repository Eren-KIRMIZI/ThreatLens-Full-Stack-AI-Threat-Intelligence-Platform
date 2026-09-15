from __future__ import annotations

"""Shared test fixtures.

An in-memory SQLite database is installed on the FastAPI app so every
dependency that needs a session (repository, history, caching) works
without touching the real development database.
"""

# Tests must never reach real upstream services, regardless of what the
# developer's local `.env` contains. Force empty external keys *before* any
# app module is imported so the first get_settings() read is deterministic.
import os

os.environ["VIRUSTOTAL_API_KEY"] = ""
os.environ["OPENROUTER_API_KEY"] = ""
os.environ["AI_ASSIST_DEFAULT"] = "false"

import asyncio

import pytest
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models.analysis import Analysis


@pytest.fixture(scope="session", autouse=True)
def test_database():
    """Create schema on a shared in-memory engine and install it on the app."""
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async def _init() -> None:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    asyncio.run(_init())

    from app.main import app

    class FakeDatabase:
        def __init__(self) -> None:
            self.engine = engine
            self.session_factory = session_factory

        async def dispose(self) -> None:
            await engine.dispose()

    app.state.database = FakeDatabase()
    return app.state.database


@pytest.fixture(autouse=True)
def _clear_analyses(test_database):
    """Reset the analyses table between tests for isolation."""

    async def _clear() -> None:
        async with test_database.session_factory() as session:
            await session.execute(delete(Analysis))
            await session.commit()

    asyncio.run(_clear())
    yield