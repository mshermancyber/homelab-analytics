"""Pi-hole v6 API ingestion — polls /api/queries for DNS query data."""
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

import httpx

from ueba.logging_config import get_logger

logger = get_logger(__name__)

_SESSION_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "pihole_sessions.json"


def _load_sessions() -> dict:
    try:
        return json.loads(_SESSION_FILE.read_text())
    except Exception:
        return {}


def _save_session(url: str, sid: str):
    sessions = _load_sessions()
    sessions[url] = sid
    _SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    _SESSION_FILE.write_text(json.dumps(sessions))


class PiHoleAPIPoller:
    """Polls Pi-hole v6 API for DNS query logs.

    Authenticates via /api/auth, then polls /api/queries periodically.
    Supports multiple Pi-hole instances (call with different URLs).
    """

    def __init__(self, pihole_url: str, pihole_password: Optional[str] = None):
        self.pihole_url = pihole_url.rstrip("/")
        self.password = pihole_password
        # verify=False is intentional: LAN Pi-hole v6 instances use self-signed
        # TLS certificates. In a homelab environment, the Pi-hole is on the same
        # trusted LAN segment, so certificate verification is not required.
        self.client = httpx.AsyncClient(timeout=30.0, verify=False)
        self._sid: Optional[str] = _load_sessions().get(pihole_url.rstrip("/"))
        self._last_id: int = 0
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._auth_backoff_until: float = 0
        self.event_callback = None
        if self._sid:
            logger.info("Pi-hole restored session from disk", extra={
                "extra_data": {"url": self.pihole_url}
            })

    async def _authenticate(self) -> bool:
        """Authenticate with Pi-hole v6 API and get session cookie."""
        if not self.password:
            logger.warning("No Pi-hole password configured, trying without auth")
            return True
        try:
            resp = await self.client.post(
                f"{self.pihole_url}/api/auth",
                json={"password": self.password},
            )
            if resp.status_code == 429:
                logger.warning("Pi-hole rate limited, backing off 120s", extra={
                    "extra_data": {"url": self.pihole_url}
                })
                self._auth_backoff_until = asyncio.get_event_loop().time() + 120
                return False
            data = resp.json()
            session = data.get("session", {})
            if session.get("valid") and session.get("sid"):
                self._sid = session["sid"]
                _save_session(self.pihole_url, self._sid)
                logger.info("Pi-hole v6 authenticated", extra={
                    "extra_data": {"url": self.pihole_url}
                })
                return True
            logger.error("Pi-hole auth failed", extra={
                "extra_data": {"status": resp.status_code, "message": session.get("message", "")}
            })
            return False
        except Exception as e:
            logger.error("Pi-hole auth error", extra={"extra_data": {"error": str(e)}})
            return False

    def _auth_headers(self) -> dict:
        if self._sid:
            return {"X-FTL-SID": self._sid}
        return {}

    async def fetch_queries(self, length: int = 200) -> List[dict]:
        """Fetch recent queries from Pi-hole v6 API."""
        now = asyncio.get_event_loop().time()
        if now < self._auth_backoff_until:
            return []
        try:
            params = {"length": length}
            if self._last_id:
                params["from"] = self._last_id
            resp = await self.client.get(
                f"{self.pihole_url}/api/queries",
                params=params,
                headers=self._auth_headers(),
            )
            if resp.status_code == 401:
                logger.info("Pi-hole session expired, re-authenticating")
                if await self._authenticate():
                    resp = await self.client.get(
                        f"{self.pihole_url}/api/queries",
                        params=params,
                        headers=self._auth_headers(),
                    )
                else:
                    return []
            resp.raise_for_status()
            data = resp.json()
            queries = data.get("queries", [])
            return queries
        except Exception as e:
            logger.error("Pi-hole query fetch failed", extra={
                "extra_data": {"error": str(e), "url": self.pihole_url}
            })
            return []

    def parse_query(self, q: dict) -> Optional[dict]:
        """Parse a Pi-hole v6 query record into normalized format."""
        try:
            status = q.get("status", "")
            blocked = status in (
                "GRAVITY", "REGEX", "DENYLIST", "EXTERNAL_BLOCKED_IP",
                "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA",
                "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME",
                "SPECIAL_DOMAIN", "DBBUSY",
            )

            ts = q.get("time")
            if isinstance(ts, (int, float)):
                timestamp = datetime.fromtimestamp(ts, tz=timezone.utc)
            else:
                timestamp = datetime.now(timezone.utc)

            client_info = q.get("client", {})
            if isinstance(client_info, dict):
                client_ip = client_info.get("ip", "0.0.0.0")
            else:
                client_ip = str(client_info)

            return {
                "timestamp": timestamp,
                "client_ip": client_ip,
                "queried_domain": q.get("domain", ""),
                "query_type": q.get("type", "A"),
                "blocked": blocked,
                "reply_type": status,
            }
        except Exception as e:
            logger.debug("Pi-hole query parse error", extra={"extra_data": {"error": str(e)}})
            return None

    async def poll_loop(self, interval: int = 10):
        """Continuous polling loop."""
        self._running = True
        if not self._sid:
            if not await self._authenticate():
                logger.error("Pi-hole initial auth failed, will retry")

        # On first poll, skip to the latest ID so we don't replay history
        if self._last_id == 0:
            try:
                queries = await self.fetch_queries(length=1)
                if queries:
                    self._last_id = max(q.get("id", 0) for q in queries)
                    logger.info("Pi-hole starting from current position", extra={
                        "extra_data": {"last_id": self._last_id, "url": self.pihole_url}
                    })
            except Exception:
                pass

        while self._running:
            try:
                queries = await self.fetch_queries()
                new_count = 0

                for q in queries:
                    qid = q.get("id", 0)
                    if qid > self._last_id:
                        parsed = self.parse_query(q)
                        if parsed and self.event_callback:
                            await self.event_callback(parsed)
                            new_count += 1

                if queries:
                    max_id = max(q.get("id", 0) for q in queries)
                    if max_id > self._last_id:
                        self._last_id = max_id

                if new_count:
                    logger.debug("Pi-hole poll", extra={
                        "extra_data": {"fetched": len(queries), "new": new_count}
                    })
            except Exception as e:
                logger.error("Pi-hole poll error", extra={"extra_data": {"error": str(e)}})

            await asyncio.sleep(interval)

    async def start(self, interval: int = 10):
        self._task = asyncio.create_task(self.poll_loop(interval))
        logger.info("Pi-hole API poller started", extra={
            "extra_data": {"url": self.pihole_url}
        })

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self.client.aclose()
        logger.info("Pi-hole API poller stopped")
