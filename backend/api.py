"""M7 read-only REST API. Run with uvicorn backend.api:app."""

from contextlib import asynccontextmanager
import logging
import os
import sqlite3

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from .storage import EventStore
from .incident_storage import IncidentStore

logger = logging.getLogger(__name__)


def create_app(database_path=None):
    """Create an app without opening a database until lifespan startup."""
    store = EventStore(database_path if database_path is not None else
                       os.environ.get("KERNELLENS_DATABASE", "kernellens.db"))
    incidents = IncidentStore(store.path)

    @asynccontextmanager
    async def lifespan(app):
        store.initialize()
        yield

    app = FastAPI(title="KernelLens", version="0.10.0", lifespan=lifespan)

    @app.exception_handler(sqlite3.Error)
    async def database_error(request: Request, error: sqlite3.Error):
        logger.error("Event database operation failed", exc_info=error)
        return JSONResponse(status_code=503, content={"detail": "Event database unavailable"})

    @app.get("/health")
    def health():
        store.check_health()
        return {"status": "ok", "database": "ok"}

    @app.get("/events")
    def events(limit: int = Query(100, ge=1, le=1000),
               offset: int = Query(0, ge=0, le=(1 << 63) - 1),
               event_category: str | None = Query(None, max_length=100),
               event_type: str | None = Query(None, max_length=100)):
        return [event.to_dict() for event in store.list_events(
            limit=limit, offset=offset, event_category=event_category, event_type=event_type)]

    @app.get("/events/{event_id}")
    def event(event_id: str):
        result = store.get(event_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Event not found")
        return result.to_dict()

    @app.get("/incidents")
    def incident_list(limit: int = Query(100, ge=1, le=1000),
                      offset: int = Query(0, ge=0, le=(1 << 63) - 1),
                      incident_type: str | None = Query(None, max_length=100),
                      severity: str | None = Query(None, max_length=100)):
        return [item.to_dict() for item in incidents.list_incidents(
            limit=limit, offset=offset, incident_type=incident_type, severity=severity)]

    @app.get("/incidents/{incident_id}")
    def incident(incident_id: str):
        result = incidents.get_incident(incident_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return result.to_dict()

    return app


app = create_app()
