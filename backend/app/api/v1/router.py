"""Aggregated v1 router."""

from fastapi import APIRouter

from app.api.v1 import analyze, analysis, health, history, reports

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(analyze.router)
api_router.include_router(analysis.router)
api_router.include_router(history.router)
api_router.include_router(reports.router)