"""Async SQLAlchemy database wiring.

SQLite (aiosqlite) is used for development; swapping DATABASE_URL to a
PostgreSQL async driver (asyncpg) enables Supabase deployment.
"""

from __future__ import annotations

from typing import AsyncIterator

from fastapi import Request
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


class Database:
    """Owns the async engine and session factory for the application."""

    def __init__(
        self,
        url: str,
        *,
        poolclass=None,
        connect_args: dict | None = None,
    ) -> None:
        kwargs: dict = {}
        if poolclass is not None:
            kwargs["poolclass"] = poolclass
        if connect_args is not None:
            kwargs["connect_args"] = connect_args
        self.engine = create_async_engine(url, **kwargs)
        self.session_factory = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    async def create_tables(self) -> None:
        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        await self.engine.dispose()


async def get_db_session(request: Request) -> AsyncIterator[AsyncSession]:
    """Yield a request-scoped async session.

    Created lazily so tests that do not run the lifespan still work.
    """
    database = getattr(request.app.state, "database", None)
    if database is None:
        database = Database(get_settings().database_url)
        request.app.state.database = database
        await database.create_tables()
    async with database.session_factory() as session:
        yield session