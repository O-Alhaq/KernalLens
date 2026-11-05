"""M11 bounded, loop-owned live delivery from committed SQLite changes."""
import asyncio
from contextlib import suppress
from dataclasses import dataclass, field
import json
import logging

from fastapi import WebSocketDisconnect

logger = logging.getLogger(__name__)
MAX_CLIENTS = 16
CLIENT_QUEUE = 256
CLIENT_BYTES = 4 * 1024 * 1024
MAX_MESSAGE_BYTES = 1024 * 1024
POLL_SECONDS = 1.0
SEND_TIMEOUT = 5.0


@dataclass(eq=False)
class Client:
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(CLIENT_QUEUE))
    bytes: int = 0
    overflow: asyncio.Event = field(default_factory=asyncio.Event)


class LiveHub:
    """All methods run on the API event loop; worker threads never touch clients."""
    def __init__(self):
        self.clients = set()

    def connect(self):
        if len(self.clients) >= MAX_CLIENTS:
            return None
        client = Client()
        self.clients.add(client)
        return client

    def disconnect(self, client):
        self.clients.discard(client)

    def publish(self, message):
        if not self.clients:
            return
        text = json.dumps(message, allow_nan=False, separators=(",", ":"))
        size = len(text.encode())
        for client in tuple(self.clients):
            if client.overflow.is_set():
                continue
            if size > MAX_MESSAGE_BYTES or client.queue.full() or client.bytes + size > CLIENT_BYTES:
                client.overflow.set()
            else:
                client.queue.put_nowait((text, size))
                client.bytes += size

    async def serve(self, websocket):
        client = self.connect()
        if client is None:
            await websocket.close(code=1013)
            return
        tasks = []
        try:
            await websocket.accept()
            await asyncio.wait_for(websocket.send_json({"schema_version": 1, "message_type": "status",
                "data": {"stream": "connected", "resync_required": True}}), timeout=SEND_TIMEOUT)

            async def send():
                while True:
                    text, size = await client.queue.get()
                    client.bytes -= size
                    await asyncio.wait_for(websocket.send_text(text), timeout=SEND_TIMEOUT)

            async def receive():
                while True:
                    message = await websocket.receive()
                    if message["type"] == "websocket.disconnect":
                        return
                    # No client commands are part of this read-only protocol.
                    await websocket.close(code=1008, reason="Server-to-client stream only")
                    return

            tasks = [asyncio.create_task(send()), asyncio.create_task(receive()),
                     asyncio.create_task(client.overflow.wait())]
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if client.overflow.is_set():
                await asyncio.wait_for(websocket.close(code=1013, reason="Live backlog; reload history"), timeout=SEND_TIMEOUT)
            for task in done:
                task.result()
        except TimeoutError:
            with suppress(WebSocketDisconnect, OSError, RuntimeError, TimeoutError):
                await asyncio.wait_for(websocket.close(code=1013, reason="Live send timeout"), timeout=SEND_TIMEOUT)
        except (WebSocketDisconnect, OSError, RuntimeError):
            pass
        finally:
            self.disconnect(client)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


async def poll_store(store, hub):
    cursors = {}
    while True:
        try:
            if hub.clients:
                messages, cursors, gap, status = await asyncio.to_thread(store.changes, cursors)
                for message in messages:
                    hub.publish(message)
                    await asyncio.sleep(0)  # Let ready socket senders drain between publications.
                hub.publish(status)
        except Exception:
            logger.exception("Dashboard live read failed; telemetry is independent")
            hub.publish({"schema_version": 1, "message_type": "status",
                         "data": {"database": "unavailable", "resync_required": True}})
        await asyncio.sleep(POLL_SECONDS)
