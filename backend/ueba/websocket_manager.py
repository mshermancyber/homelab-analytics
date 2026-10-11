"""WebSocket manager for live event feed streaming."""
import asyncio
import json
from typing import Set, Dict, Any

from fastapi import WebSocket

from ueba.logging_config import get_logger

logger = get_logger(__name__)


class WebSocketManager:
    """Manages WebSocket connections for live event streaming."""

    def __init__(self):
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()
        self._event_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._broadcast_task: asyncio.Task = None
        self._running = False

    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)
        logger.debug("WebSocket connected", extra={
            "extra_data": {"total_connections": len(self._connections)}
        })

    async def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        async with self._lock:
            self._connections.discard(websocket)
        logger.debug("WebSocket disconnected", extra={
            "extra_data": {"total_connections": len(self._connections)}
        })

    async def broadcast(self, event_type: str, data: Dict[str, Any]):
        """Broadcast an event to all connected WebSocket clients."""
        message = json.dumps({"type": event_type, "data": data})
        try:
            self._event_queue.put_nowait(message)
        except asyncio.QueueFull:
            logger.debug("WebSocket event queue full, dropping event")

    async def _broadcast_worker(self):
        """Worker that sends queued events to all connections."""
        while self._running:
            try:
                try:
                    message = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue

                async with self._lock:
                    dead: Set[WebSocket] = set()
                    for ws in self._connections:
                        try:
                            await ws.send_text(message)
                        except Exception:
                            dead.add(ws)

                    for ws in dead:
                        self._connections.discard(ws)

                self._event_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("WebSocket broadcast error", extra={"extra_data": {"error": str(e)}})

    async def start(self):
        """Start the broadcast worker."""
        self._running = True
        self._broadcast_task = asyncio.create_task(self._broadcast_worker())
        logger.info("WebSocket manager started")

    async def stop(self):
        """Stop the broadcast worker and close all connections."""
        self._running = False
        if self._broadcast_task:
            self._broadcast_task.cancel()
            try:
                await self._broadcast_task
            except asyncio.CancelledError:
                pass

        async with self._lock:
            for ws in self._connections:
                try:
                    await ws.close()
                except Exception:
                    pass
            self._connections.clear()

        logger.info("WebSocket manager stopped")

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    @property
    def queue_depth(self) -> int:
        return self._event_queue.qsize()
