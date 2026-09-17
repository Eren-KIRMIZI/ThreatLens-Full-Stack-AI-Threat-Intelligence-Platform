"""ThreatLens API application entrypoint.

Factory-based app creation keeps imports testable and avoids shared state.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.database import Database
from app.core.exceptions import register_exception_handlers
from app.core.logging import setup_logging
from app.services.virustotal_service import VirusTotalService

settings = get_settings()
setup_logging(settings.log_level)


@asynccontextmanager
async def lifespan(application: FastAPI):
    database = Database(settings.database_url)
    if settings.environment == "development":
        # Schema is managed by Alembic in production (e.g. Supabase).
        await database.create_tables()
    application.state.database = database
    application.state.virustotal_service = VirusTotalService()
    yield
    names = (
        "virustotal_service",
        "openrouter_service",
        "enrichment_service",
    )
    for attr in names:
        service = getattr(application.state, attr, None)
        if service is not None and hasattr(service, "aclose"):
            await service.aclose()
    await database.dispose()


def create_app() -> FastAPI:
    application = FastAPI(
        title="ThreatLens API",
        description=(
            "AI-assisted threat intelligence platform powered by "
            "VirusTotal evidence and OpenRouter interpretation."
        ),
        version=settings.app_version,
        openapi_url=f"{settings.api_prefix}/openapi.json",
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(api_router, prefix=settings.api_prefix)

    register_exception_handlers(application)

    @application.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        return {
            "service": "ThreatLens API",
            "status": "operational",
            "docs": "/docs",
        }

    return application


app = create_app()