from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI

from src.config import Settings
from src.instagram_client import InstagramClientService
from src.routes.health import router as health_router
from src.routes.instagram_internal import router as internal_router
from src.security.encryption import EncryptionService
from src.services.audit import AuditService
from src.services.polling import PollingService
from src.session_store import MemorySessionStore, MongoSessionStore


def create_app(
    *,
    settings: Settings,
    session_store: MongoSessionStore | MemorySessionStore,
    audit: AuditService,
    instagram: InstagramClientService,
) -> FastAPI:
    docs_url = "/docs" if settings.app_env == "development" else None
    redoc_url = "/redoc" if settings.app_env == "development" else None
    openapi_url = "/openapi.json" if settings.app_env == "development" else None

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await audit.record("SERVICE_STARTED")
        try:
            await session_store.ensure_indexes()
            connected = await session_store.ping()
            await audit.record("MONGODB_CONNECTED" if connected else "MONGODB_CONNECTION_FAILED")
        except Exception:
            await audit.record("MONGODB_CONNECTION_FAILED")
        polling = PollingService(settings, audit)
        await polling.start()
        app.state.polling = polling
        try:
            yield
        finally:
            await session_store.close()

    app = FastAPI(
        title="instagram-aiograpi-experimental",
        version=settings.app_version,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.session_store = session_store
    app.state.audit = audit
    app.state.instagram = instagram
    app.include_router(health_router)
    app.include_router(internal_router)
    return app


def create_runtime_app() -> FastAPI:
    settings = Settings.from_env()
    encryption = EncryptionService(settings.session_encryption_key)
    session_store = MongoSessionStore(settings, encryption)
    audit = AuditService(collection_provider=session_store.audit_collection)
    instagram = InstagramClientService(settings, session_store, audit)
    return create_app(settings=settings, session_store=session_store, audit=audit, instagram=instagram)
