"""Database setup - SQLite via SQLAlchemy with aiosqlite async driver."""
import asyncio
import os
from pathlib import Path
from typing import Any, Callable, Awaitable
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from ueba.logging_config import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Write serialization: all writes go through a single worker to avoid
# SQLite 'database is locked' errors from concurrent write attempts.
# ---------------------------------------------------------------------------

_write_queue: asyncio.Queue = asyncio.Queue()
_writer_task: asyncio.Task | None = None


async def _db_writer() -> None:
    """Serialized write worker: pulls callables from the queue and executes them
    one at a time.  Results (or exceptions) are forwarded to the caller via
    the Future that was stored alongside the callable."""
    while True:
        coro_factory: Callable[[], Awaitable[Any]]
        future: asyncio.Future
        coro_factory, future = await _write_queue.get()
        try:
            result = await coro_factory()
            if not future.done():
                future.set_result(result)
        except Exception as exc:
            logger.error("Write operation failed", extra={"extra_data": {"error": str(exc)}})
            if not future.done():
                future.set_exception(exc)
        finally:
            _write_queue.task_done()


async def submit_write(coro_factory: Callable[[], Awaitable[Any]]) -> Any:
    """Enqueue an async write callable and wait for the serialized result.

    Usage::

        async def _do_write():
            async with async_session_factory() as session:
                ...
                return result
        result = await submit_write(_do_write)
    """
    future: asyncio.Future = asyncio.get_event_loop().create_future()
    await _write_queue.put((coro_factory, future))
    return await future


async def start_writer() -> None:
    """Launch the background write worker."""
    global _writer_task
    if _writer_task is None or _writer_task.done():
        _writer_task = asyncio.create_task(_db_writer())
        logger.info("Database write worker started")


async def stop_writer() -> None:
    """Cancel the background write worker and wait for it to finish."""
    global _writer_task
    if _writer_task and not _writer_task.done():
        _writer_task.cancel()
        try:
            await _writer_task
        except asyncio.CancelledError:
            pass
        logger.info("Database write worker stopped")

DB_PATH = os.environ.get("UEBA_DB_PATH", str(Path(__file__).resolve().parent.parent / "data" / "ueba.db"))

# Ensure data directory exists
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"

engine = create_async_engine(
    DATABASE_URL, echo=False,
    connect_args={"check_same_thread": False, "timeout": 30},
    pool_size=5, max_overflow=10,
)

async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def init_db() -> None:
    """Create all tables on startup."""
    from ueba.models import (  # noqa: F401
        SyslogEvent, OPNsenseLog, PiHoleQuery, ThreatFeed, ThreatMatch,
        BehavioralFlag, Alert, LLMCache, NetworkBaseline, User, CustomRule,
        AnomalySuppression, FalsePositivePattern, ShadowResult, BuildingBlock,
        DeviceRole, ModelRun, DeviceProfile, DGATrainingLabel, PolicyBaseline,
    )
    from ueba.analytics.first_seen import FirstSeenHistory  # noqa: F401
    from ueba.models import BaselineSnapshot, DNSHostProfile  # noqa: F401
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Run migrations
        import sqlalchemy as sa
        migrations = [
            "ALTER TABLE alerts ADD COLUMN attack_technique VARCHAR(20)",
            "ALTER TABLE alerts ADD COLUMN attack_tactic VARCHAR(50)",
            "ALTER TABLE alerts ADD COLUMN investigation_guide TEXT",
            "ALTER TABLE custom_rules ADD COLUMN maturity_status VARCHAR(20) DEFAULT 'active'",
            "ALTER TABLE custom_rules ADD COLUMN deprecation_reason TEXT",
        ]
        for m in migrations:
            try:
                await conn.execute(sa.text(m))
            except Exception:
                pass  # Column already exists
        await conn.execute(sa.text("PRAGMA journal_mode=WAL"))
        await conn.execute(sa.text("PRAGMA synchronous=NORMAL"))
        await conn.execute(sa.text("PRAGMA busy_timeout=5000"))
    logger.info("Database initialized", extra={"extra_data": {"path": DB_PATH}})


async def get_session() -> AsyncSession:
    """Dependency for FastAPI to get an async session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def shutdown_db() -> None:
    """Gracefully dispose of the engine."""
    await engine.dispose()
    logger.info("Database engine disposed")
