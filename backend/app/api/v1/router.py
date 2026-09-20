"""Aggregated v1 router."""

from fastapi import APIRouter

from app.api.v1 import (
    analyze,
    analysis,
    exports,
    forensics,
    health,
    history,
    intel,
    investigations,
    iocs,
    reports,
    watchlist,
)

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(analyze.router)
api_router.include_router(analysis.router)
api_router.include_router(history.router)
api_router.include_router(reports.router)
api_router.include_router(iocs.router)
api_router.include_router(investigations.router)
api_router.include_router(watchlist.router)
api_router.include_router(intel.router)
api_router.include_router(exports.router)
api_router.include_router(forensics.router)