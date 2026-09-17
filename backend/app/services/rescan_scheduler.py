"""Optional background rescan scheduler.

When ``WATCHLIST_RESCAN_INTERVAL_SECONDS`` is > 0 the app re-analyzes every
enabled watchlist item on that cadence and evaluates the alert rules. Disabled
by default: rescans remain available on demand via ``POST /watchlist/rescan/all``.
"""

from __future__ import annotations

import asyncio
import contextlib

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.repositories.analysis_repository import AnalysisRepository
from app.repositories.registry_repository import RegistryRepository
from app.repositories.watchlist_repository import WatchlistRepository
from app.services.ai_service import AIService
from app.services.analysis_service import AnalysisService
from app.services.openrouter_service import OpenRouterService
from app.services.rescan_service import RescanService
from app.services.virustotal_service import VirusTotalService

logger = get_logger(__name__)

_tasks: list[asyncio.Task] = []


def _build_rescan(application: FastAPI) -> tuple[RescanService, AsyncSession, OpenRouterService]:
    database = application.state.database
    session: AsyncSession = database.session_factory()
    registry = RegistryRepository(session)
    watchlist = WatchlistRepository(session)
    analysis_repository = AnalysisRepository(session)
    vt = getattr(application.state, "virustotal_service", None) or VirusTotalService()
    openrouter = OpenRouterService()
    ai = AIService(openrouter)
    analysis = AnalysisService(
        vt, analysis_repository, ai, enrichment=None, registry=registry
    )
    return RescanService(analysis, watchlist, registry), session, openrouter


async def _run_loop(application: FastAPI, interval: int) -> None:
    while True:
        await asyncio.sleep(interval)
        session: AsyncSession | None = None
        openrouter: OpenRouterService | None = None
        try:
            rescan, session, openrouter = _build_rescan(application)
            report = await rescan.rescan_all()
            logger.info(
                "scheduled watchlist rescan completed",
                checked=report.checked,
                rule_hits=sum(len(item.alerts) for item in report.outcomes),
            )
        except Exception:
            logger.exception("scheduled watchlist rescan failed")
        finally:
            with contextlib.suppress(Exception):
                if session is not None:
                    await session.close()
            with contextlib.suppress(Exception):
                if openrouter is not None:
                    await openrouter.aclose()


async def start_scheduler(application: FastAPI) -> None:
    interval = get_settings().watchlist_rescan_interval_seconds
    if interval <= 0:
        return
    global _tasks
    _tasks.append(asyncio.get_running_loop().create_task(_run_loop(application, interval)))
    logger.info("watchlist rescan scheduler started", interval_seconds=interval)


async def stop_scheduler() -> None:
    global _tasks
    for task in _tasks:
        task.cancel()
    for task in _tasks:
        with contextlib.suppress(asyncio.CancelledError):
            await task
    _tasks = []