"""M7 read-only REST API. Run with uvicorn backend.api:app."""

from contextlib import asynccontextmanager, suppress
import asyncio
import logging
import os
import sqlite3

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from .storage import EventStore
from .incident_storage import IncidentStore
from .dashboard_storage import DashboardStore
from .live import LiveHub, poll_store

logger = logging.getLogger(__name__)


def create_app(database_path=None):
    """Create an app without opening a database until lifespan startup."""
    store = EventStore(database_path if database_path is not None else
                       os.environ.get("KERNELLENS_DATABASE", "kernellens.db"))
    incidents = IncidentStore(store.path)
    dashboard = DashboardStore(store.path)
    hub = LiveHub()
    origins = [item.strip() for item in os.environ.get("KERNELLENS_UI_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173").split(",") if item.strip()]
    if "*" in origins:
        raise ValueError("explicit dashboard origins required")

    @asynccontextmanager
    async def lifespan(app):
        await asyncio.to_thread(store.initialize)
        task = asyncio.create_task(poll_store(dashboard, hub))
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="KernelLens", version="0.11.0", lifespan=lifespan)

    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET"], allow_headers=[])
    app.state.live = hub

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
               event_type: str | None = Query(None, max_length=100),
               newest_first: bool = False):
        return dashboard.operator_records("event", [event.to_dict() for event in store.list_events(
            limit=limit, offset=offset, event_category=event_category, event_type=event_type, newest_first=newest_first)])

    @app.get("/events/{event_id}")
    def event(event_id: str):
        result = store.get(event_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Event not found")
        return dashboard.operator_record("event", result.to_dict())

    @app.get("/incidents")
    def incident_list(limit: int = Query(100, ge=1, le=1000),
                      offset: int = Query(0, ge=0, le=(1 << 63) - 1),
                      incident_type: str | None = Query(None, max_length=100),
                      severity: str | None = Query(None, max_length=100),
                      newest_first: bool = False):
        return dashboard.operator_records("incident", [item.to_dict() for item in incidents.list_incidents(
            limit=limit, offset=offset, incident_type=incident_type, severity=severity, newest_first=newest_first)])

    @app.get("/incidents/{incident_id}")
    def incident(incident_id: str):
        result = incidents.get_incident(incident_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return dashboard.operator_record("incident", result.to_dict())

    @app.get("/alerts")
    def alerts(limit: int = Query(100, ge=1, le=1000),
               offset: int = Query(0, ge=0, le=(1 << 63) - 1),
               severity: str | None = Query(None, max_length=100),
               event_category: str | None = Query(None, max_length=100),
               alert_type: str | None = Query(None, max_length=100),
               newest_first: bool = False):
        return dashboard.operator_records("alert", incidents.list_alerts(limit=limit, offset=offset, severity=severity,
            event_category=event_category, alert_type=alert_type, newest_first=newest_first))

    @app.get("/alerts/{alert_id}")
    def alert(alert_id: str):
        result = incidents.get_alert(alert_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return dashboard.operator_record("alert", result.to_dict())

    @app.get("/dashboard/summary")
    def summary():
        return dashboard.summary()

    @app.get("/dashboard/snapshot")
    def snapshot():
        return dashboard.snapshot()

    @app.websocket("/ws/live")
    async def live(websocket: WebSocket):
        origin = websocket.headers.get("origin")
        if origin is not None and origin not in origins:
            await websocket.close(code=1008)
            return
        await hub.serve(websocket)

    return app


app = create_app()
