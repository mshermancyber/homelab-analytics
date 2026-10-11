"""FastAPI application for UEBA platform - all API routes and WebSocket endpoint."""
import asyncio
import json
import os
import signal
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query, Body, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel


class RegisterRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class LoginRequest(BaseModel):
    username: str
    password: str


class ChatRequest(BaseModel):
    message: str
    alert_id: Optional[int] = None


class SuppressionRequest(BaseModel):
    ip: str
    detector_name: str


class CustomRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    rule_json: str
    severity: str = "medium"
    enabled: bool = True


class CustomRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    rule_json: Optional[str] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None


class FpPatternCreate(BaseModel):
    detector_name: str
    src_pattern: Optional[str] = None
    dst_pattern: Optional[str] = None
    domain_pattern: Optional[str] = None
    classification: str
    reason: Optional[str] = None


class DeviceRoleCreate(BaseModel):
    ip: str
    role: str
    label: Optional[str] = None


class DeviceRoleUpdate(BaseModel):
    role: Optional[str] = None
    label: Optional[str] = None


class RuleTestRequest(BaseModel):
    rule_json: str
    name: str
    severity: str = "medium"


class RulePromoteRequest(BaseModel):
    pass


class RuleDeprecateRequest(BaseModel):
    reason: str
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from ueba.logging_config import setup_logging, get_logger
from ueba.config import get_config, reload_config
from ueba.netconfig import is_internal
from ueba.database import get_session, async_session_factory
from ueba.models import (
SyslogEvent, OPNsenseLog, PiHoleQuery, ThreatFeed, ThreatMatch,
BehavioralFlag, Alert, LLMCache, NetworkBaseline, User,
AnomalySuppression, FalsePositivePattern, ShadowResult, DeviceRole,
ModelRun, BuildingBlock, DGATrainingLabel, CustomRule,
)
from ueba.auth import (
    create_access_token, decode_access_token, authenticate_user,
    create_user, has_permission, hash_password,
)
from ueba.engine import UEBAEngine, init_engine, get_engine
from ueba.websocket_manager import WebSocketManager
from ueba.chat import stream_chat, _check_rate_limit
from ueba.analytics.playbooks import PLAYBOOKS
from ueba.analytics.attack_mapping import get_mitre_mapping, MITRE_MAPPING

logger = get_logger(__name__)


def _utc_iso(dt) -> Optional[str]:
    """Convert a datetime to ISO string with UTC timezone suffix."""
    if not dt:
        return None
    s = dt.isoformat()
    if not s.endswith(("Z", "+00:00", "-")) and "+" not in s[19:]:
        s += "Z"
    return s

# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - startup and shutdown."""
    config = get_config()
    setup_logging(config.logging.level)

    logger.info("Starting UEBA Platform", extra={
        "extra_data": {"version": "0.1.0"}
    })

    # Initialize the engine
    engine = await init_engine()
    app.state.engine = engine

    # Start the serialized database writer
    from ueba.database import start_writer
    await start_writer()

    # Set up signal handlers
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(_graceful_shutdown(app)))

    yield

    # Shutdown
    logger.info("UEBA Platform shutting down")
    from ueba.database import stop_writer
    await stop_writer()
    await engine.shutdown()


async def _graceful_shutdown(app: FastAPI):
    """Handle graceful shutdown."""
    logger.info("Received shutdown signal")
    engine = getattr(app.state, "engine", None)
    if engine:
        await engine.shutdown()


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="UEBA Platform",
        description="User and Entity Behavior Analytics for home and lab networks",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -----------------------------------------------------------------------
    # Auth dependencies
    # -----------------------------------------------------------------------

    async def get_current_user(
        authorization_header: Optional[str] = Header(None, alias="Authorization"),
        authorization_query: Optional[str] = Query(None, alias="authorization"),
        session: AsyncSession = Depends(get_session),
    ) -> User:
        """Dependency: get current authenticated user from JWT.
        
        Accepts token via Authorization header (Bearer scheme) — the standard HTTP approach.
        Also accepts a fallback query parameter for WebSocket upgrade negotiation.
        """
        raw = authorization_header or authorization_query
        token = None
        if raw:
            token = raw.replace("Bearer ", "")
        if not token:
            raise HTTPException(status_code=401, detail="Authorization header required")

        payload = decode_access_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid or expired token")

        result = await session.execute(select(User).where(User.id == payload["user_id"]))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return user

    def require_role(*roles: str):
        """Dependency factory: require one of the given roles."""
        async def _check(user: User = Depends(get_current_user)) -> User:
            if user.role not in roles:
                raise HTTPException(status_code=403, detail=f"Requires role: {' or '.join(roles)}")
            return user
        return _check

    require_admin = require_role("admin")
    require_analyst = require_role("admin", "analyst")

    # -----------------------------------------------------------------------
    # Health check
    # -----------------------------------------------------------------------

    @app.get("/api/health")
    async def health_check():
        """Health check endpoint returning feed status, listener status, queue depth."""
        engine = getattr(app.state, "engine", None)
        if engine:
            return await engine.health_check()
        return {"status": "starting"}

    # -----------------------------------------------------------------------
    # Auth endpoints
    # -----------------------------------------------------------------------

    @app.post("/api/auth/register")
    async def register(
        body: RegisterRequest,
        session: AsyncSession = Depends(get_session),
    ):
        """Register a new user."""
        result = await session.execute(select(User).where(User.username == body.username))
        existing = result.scalar_one_or_none()
        if existing:
            raise HTTPException(status_code=409, detail="Username already exists")

        if body.role not in ("admin", "analyst", "viewer"):
            raise HTTPException(status_code=400, detail="Invalid role")

        user = await create_user(session, body.username, body.password, body.role)

        # Auto-login: return token
        token = create_access_token(body.username, user.role, user.id)
        return {
            "user_id": user.id,
            "username": user.username,
            "role": user.role,
            "access_token": token,
        }

    @app.post("/api/auth/login")
    async def login(
        body: LoginRequest,
        session: AsyncSession = Depends(get_session),
    ):
        """Login and receive JWT token."""
        user = await authenticate_user(session, body.username, body.password)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        token = create_access_token(body.username, user.role, user.id)
        return {
            "user_id": user.id,
            "username": user.username,
            "role": user.role,
            "access_token": token,
        }

    @app.get("/api/auth/me")
    async def me(user: User = Depends(get_current_user)):
        """Get current user info."""
        return {
            "user_id": user.id,
            "username": user.username,
            "role": user.role,
            "permissions": list({"admin": set(), "analyst": set(), "viewer": set()}.get(user.role, set())),
        }

    @app.get("/api/auth/users")
    async def list_users(
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_admin),
    ):
        """List all users (admin only)."""
        result = await session.execute(select(User).order_by(User.username))
        users = result.scalars().all()
        return [
            {
                "id": u.id,
                "username": u.username,
                "role": u.role,
                "created_at": u.created_at.isoformat() + 'Z' if u.created_at else None,
            }
            for u in users
        ]

    # -----------------------------------------------------------------------
    # Event endpoints
    # -----------------------------------------------------------------------

    @app.get("/api/events")
    async def list_events(
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
        event_type: Optional[str] = Query(None),
        source_ip: Optional[str] = Query(None),
        since: Optional[str] = Query(None),
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """List events with optional filters."""
        query = select(SyslogEvent)

        if event_type:
            query = query.where(SyslogEvent.event_type == event_type)
        if source_ip:
            query = query.where(SyslogEvent.source_ip == source_ip)
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
                query = query.where(SyslogEvent.received_at >= since_dt)
            except ValueError:
                pass

        query = query.order_by(desc(SyslogEvent.received_at)).offset(offset).limit(limit)

        result = await session.execute(query)
        events = result.scalars().all()

        return [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat() + "Z" if e.timestamp else None,
                "source_ip": e.source_ip,
                "source_device": e.source_device,
                "raw_message": e.raw_message[:500] if e.raw_message else "",
                "parsed_fields": e.parsed_fields,
                "event_type": e.event_type,
                "received_at": e.received_at.isoformat() + "Z" if e.received_at else None,
            }
            for e in events
        ]

    @app.get("/api/events/{event_id}")
    async def get_event_detail(
        event_id: int,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Get full event detail including threat matches, behavioral flags, and LLM analysis."""
        # Get the event
        result = await session.execute(
            select(SyslogEvent).where(SyslogEvent.id == event_id)
        )
        event = result.scalar_one_or_none()
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")

        # Get threat matches
        tm_result = await session.execute(
            select(ThreatMatch).where(ThreatMatch.event_id == event_id)
        )
        threat_matches = tm_result.scalars().all()

        # Get behavioral flags
        bf_result = await session.execute(
            select(BehavioralFlag).where(BehavioralFlag.event_id == event_id)
        )
        behavioral_flags = bf_result.scalars().all()

        # Get related alerts
        alert_result = await session.execute(
            select(Alert).where(Alert.event_ids.contains([event_id]))
        )
        related_alerts = alert_result.scalars().all()

        return {
            "event": {
                "id": event.id,
                "timestamp": event.timestamp.isoformat() + "Z" if event.timestamp else None,
                "source_ip": event.source_ip,
                "source_device": event.source_device,
                "raw_message": event.raw_message,
                "parsed_fields": event.parsed_fields,
                "event_type": event.event_type,
                "received_at": event.received_at.isoformat() + "Z" if event.received_at else None,
            },
            "threat_matches": [
                {
                    "id": tm.id,
                    "ioc_value": tm.ioc_value,
                    "threat_category": tm.threat_category,
                    "severity_hint": tm.severity_hint,
                    "feed_id": tm.feed_id,
                    "first_seen": tm.first_seen.isoformat() + "Z" if tm.first_seen else None,
                }
                for tm in threat_matches
            ],
            "behavioral_flags": [
                {
                    "id": bf.id,
                    "flag_type": bf.flag_type,
                    "details": bf.details,
                    "timestamp": bf.timestamp.isoformat() + "Z" if bf.timestamp else None,
                }
                for bf in behavioral_flags
            ],
            "alerts": [
                {
                    "id": a.id,
                    "severity": a.severity,
                    "classification": a.classification,
                    "escalate": a.escalate,
                    "confidence": a.confidence,
                    "llm_analysis": a.llm_analysis,
                    "created_at": a.created_at.isoformat() + "Z" if a.created_at else None,
                }
                for a in related_alerts
            ],
        }

    # -----------------------------------------------------------------------
    # Custom Rules endpoints
    # -----------------------------------------------------------------------

    @app.get("/api/rules")
    async def list_rules(
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """List all custom rules."""
        result = await session.execute(
            select(CustomRule).order_by(CustomRule.created_at.desc())
        )
        rules = result.scalars().all()
        return [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "rule_json": r.rule_json,
                "severity": r.severity,
                "enabled": r.enabled,
                "maturity_status": getattr(r, "maturity_status", "active"),
                "deprecation_reason": getattr(r, "deprecation_reason", None),
                "playbook": "## Custom Rule Investigation Playbook\n1. Review the rule match details to understand what triggered this detection.\n2. Check if the matched event corresponds to a known and authorized activity.\n3. Correlate with other alerts from the same source IP for pattern analysis.\n4. If benign, mark as false positive to train suppression.\n5. If suspicious, escalate to incident response.\n6. Review rule performance monthly — disable if FP rate exceeds 50%.",
                "created_at": r.created_at.isoformat() + "Z" if r.created_at else None,
                "updated_at": r.updated_at.isoformat() + "Z" if r.updated_at else None,
            }
            for r in rules
        ]

    @app.post("/api/rules")
    async def create_rule(
        body: CustomRuleCreate,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Create a new custom rule."""
        valid_severities = {"critical", "high", "medium", "low", "info"}
        if body.severity not in valid_severities:
            raise HTTPException(400, f"Invalid severity. Must be one of: {valid_severities}")

        # Validate rule_json is valid JSON
        try:
            json.loads(body.rule_json)
        except json.JSONDecodeError:
            raise HTTPException(400, "rule_json must be valid JSON")

        rule = CustomRule(
            name=body.name,
            description=body.description,
            rule_json=body.rule_json,
            severity=body.severity,
            enabled=body.enabled,
            maturity_status="experimental",
        )
        session.add(rule)
        await session.commit()
        await session.refresh(rule)

        # Reload rules in engine
        engine = get_engine()
        await engine.reload_rules()

        custom_rule_playbook = "## Custom Rule Investigation Playbook\n1. Review the rule match details to understand what triggered this detection.\n2. Check if the matched event corresponds to a known and authorized activity.\n3. Correlate with other alerts from the same source IP for pattern analysis.\n4. If benign, mark as false positive to train suppression.\n5. If suspicious, escalate to incident response.\n6. Review rule performance monthly — disable if FP rate exceeds 50%."

        return {
            "id": rule.id,
            "name": rule.name,
            "description": rule.description,
            "rule_json": rule.rule_json,
            "severity": rule.severity,
            "enabled": rule.enabled,
            "maturity_status": getattr(rule, "maturity_status", "experimental"),
            "deprecation_reason": getattr(rule, "deprecation_reason", None),
            "playbook": custom_rule_playbook,
            "created_at": rule.created_at.isoformat() + "Z" if rule.created_at else None,
            "updated_at": rule.updated_at.isoformat() + "Z" if rule.updated_at else None,
        }

    @app.put("/api/rules/{rule_id}")
    async def update_rule(
        rule_id: int,
        body: CustomRuleUpdate,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Update an existing custom rule."""
        result = await session.execute(select(CustomRule).where(CustomRule.id == rule_id))
        rule = result.scalar_one_or_none()
        if not rule:
            raise HTTPException(404, "Rule not found")

        # Prevent editing deprecated rules
        maturity = getattr(rule, "maturity_status", "active")
        if maturity == "deprecated":
            raise HTTPException(400, "Cannot edit a deprecated rule")

        if body.name is not None:
            rule.name = body.name
        if body.description is not None:
            rule.description = body.description
        if body.rule_json is not None:
            try:
                json.loads(body.rule_json)
            except json.JSONDecodeError:
                raise HTTPException(400, "rule_json must be valid JSON")
            rule.rule_json = body.rule_json
        if body.severity is not None:
            valid_severities = {"critical", "high", "medium", "low", "info"}
            if body.severity not in valid_severities:
                raise HTTPException(400, f"Invalid severity. Must be one of: {valid_severities}")
            rule.severity = body.severity
        if body.enabled is not None:
            rule.enabled = body.enabled

        rule.updated_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(rule)

        # Reload rules in engine
        engine = get_engine()
        await engine.reload_rules()

        custom_rule_playbook = "## Custom Rule Investigation Playbook\n1. Review the rule match details to understand what triggered this detection.\n2. Check if the matched event corresponds to a known and authorized activity.\n3. Correlate with other alerts from the same source IP for pattern analysis.\n4. If benign, mark as false positive to train suppression.\n5. If suspicious, escalate to incident response.\n6. Review rule performance monthly — disable if FP rate exceeds 50%."

        return {
            "id": rule.id,
            "name": rule.name,
            "description": rule.description,
            "rule_json": rule.rule_json,
            "severity": rule.severity,
            "enabled": rule.enabled,
            "maturity_status": getattr(rule, "maturity_status", "active"),
            "deprecation_reason": getattr(rule, "deprecation_reason", None),
            "playbook": custom_rule_playbook,
            "created_at": rule.created_at.isoformat() + "Z" if rule.created_at else None,
            "updated_at": rule.updated_at.isoformat() + "Z" if rule.updated_at else None,
        }

    @app.delete("/api/rules/{rule_id}")
    async def delete_rule(
        rule_id: int,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Delete a custom rule."""
        result = await session.execute(select(CustomRule).where(CustomRule.id == rule_id))
        rule = result.scalar_one_or_none()
        if not rule:
            raise HTTPException(404, "Rule not found")

        await session.delete(rule)
        await session.commit()

        # Reload rules in engine
        engine = get_engine()
        await engine.reload_rules()

        return {"status": "deleted", "id": rule_id}

    # -----------------------------------------------------------------------
    # Alert endpoints
    # -----------------------------------------------------------------------

    @app.get("/api/alerts/top-offenders")
    async def top_offenders(
        days: int = Query(7, ge=1, le=90),
        limit: int = Query(20, ge=1, le=100),
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Get top offending hosts by alert count."""
        since = datetime.now(timezone.utc) - timedelta(days=days)

        # Top source IPs
        src_result = await session.execute(
            select(Alert.src_ip, func.count(Alert.id).label("count"))
            .where(Alert.created_at >= since)
            .group_by(Alert.src_ip)
            .order_by(desc("count"))
            .limit(limit)
        )
        top_sources = [{"src_ip": row[0], "alert_count": row[1]} for row in src_result]

        # Top destination IPs
        dst_result = await session.execute(
            select(Alert.dst_ip, func.count(Alert.id).label("count"))
            .where(Alert.created_at >= since, Alert.dst_ip.isnot(None), Alert.dst_ip != "")
            .group_by(Alert.dst_ip)
            .order_by(desc("count"))
            .limit(limit)
        )
        top_destinations = [{"dst_ip": row[0], "alert_count": row[1]} for row in dst_result]

        # Enrich top destinations with geo/org from most recent alert
        dst_ips = [d["dst_ip"] for d in top_destinations]
        if dst_ips:
            enrich_result = await session.execute(
                select(Alert.dst_ip, Alert.llm_analysis)
                .where(Alert.created_at >= since, Alert.dst_ip.in_(dst_ips))
                .order_by(desc(Alert.created_at))
            )
            dst_enrichment: dict = {}
            for row in enrich_result:
                ip = row[0]
                if ip in dst_enrichment:
                    continue
                da = row[1]
                if isinstance(da, dict):
                    enr = da.get("enrichment", {}).get(ip, {})
                    if enr:
                        dst_enrichment[ip] = {
                            "country": enr.get("country"),
                            "country_code": enr.get("country_code"),
                            "org": enr.get("org") or enr.get("isp"),
                            "asn": enr.get("asn"),
                            "reverse_dns": enr.get("reverse_dns"),
                        }
            for d in top_destinations:
                d.update(dst_enrichment.get(d["dst_ip"], {}))

        # Severity breakdown
        sev_result = await session.execute(
            select(Alert.severity, func.count(Alert.id).label("count"))
            .where(Alert.created_at >= since)
            .group_by(Alert.severity)
        )
        severity_breakdown = {row[0]: row[1] for row in sev_result}

        # Top classifications
        class_result = await session.execute(
            select(Alert.classification, func.count(Alert.id).label("count"))
            .where(Alert.created_at >= since)
            .group_by(Alert.classification)
            .order_by(desc("count"))
            .limit(10)
        )
        top_classifications = [{"classification": row[0], "count": row[1]} for row in class_result]

        return {
            "top_sources": top_sources,
            "top_destinations": top_destinations,
            "severity_breakdown": severity_breakdown,
            "top_classifications": top_classifications,
            "period_days": days,
        }

    @app.get("/api/alerts")
    async def list_alerts(
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
        severity: Optional[str] = Query(None),
        classification: Optional[str] = Query(None),
        source_ip: Optional[str] = Query(None),
        escalate: Optional[bool] = Query(None),
        action: Optional[str] = Query(None),
        since: Optional[str] = Query(None),
        until: Optional[str] = Query(None),
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """List alerts with filters."""
        query = select(Alert)

        if severity:
            query = query.where(Alert.severity == severity)
        if classification:
            query = query.where(Alert.classification.ilike(f"%{classification}%"))
        if source_ip:
            query = query.where(Alert.src_ip == source_ip)
        if escalate is not None:
            query = query.where(Alert.escalate == escalate)
        if action:
            query = query.where(Alert.firewall_action == action)
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
                query = query.where(Alert.created_at >= since_dt)
            except ValueError:
                pass
        if until:
            try:
                until_dt = datetime.fromisoformat(until)
                query = query.where(Alert.created_at <= until_dt)
            except ValueError:
                pass

        query = query.order_by(desc(Alert.created_at)).offset(offset).limit(limit)

        result = await session.execute(query)
        alerts = result.scalars().all()

        return [
            {
                "id": a.id,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "severity": a.severity,
                "classification": a.classification,
                "escalate": a.escalate,
                "confidence": a.confidence,
                "threat_matches": a.threat_matches,
                "behavioral_flags": a.behavioral_flags,
                "llm_analysis": a.llm_analysis,
                "firewall_action": a.firewall_action,
                "dst_domain": a.dst_domain,
                "status": getattr(a, "status", "open"),
                "attack_technique": a.attack_technique,
                "attack_tactic": a.attack_tactic,
                "created_at": a.created_at.isoformat() + "Z" if a.created_at else None,
            }
            for a in alerts
        ]

    @app.get("/api/alerts/{alert_id}")
    async def get_alert_detail(
        alert_id: int,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Get full alert detail including linked events, threat matches, and behavioral flags."""
        result = await session.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            raise HTTPException(404, "Alert not found")

        event_ids = alert.event_ids or []
        linked_events = []
        all_threat_matches = []
        all_behavioral_flags = []

        for eid in event_ids:
            ev_result = await session.execute(select(SyslogEvent).where(SyslogEvent.id == eid))
            ev = ev_result.scalar_one_or_none()
            if ev:
                linked_events.append({
                    "id": ev.id,
                    "timestamp": ev.timestamp.isoformat() + "Z" if ev.timestamp else None,
                    "source_ip": ev.source_ip,
                    "source_device": ev.source_device,
                    "raw_message": ev.raw_message,
                    "parsed_fields": ev.parsed_fields,
                    "event_type": ev.event_type,
                    "received_at": ev.received_at.isoformat() + "Z" if ev.received_at else None,
                })
            tm_result = await session.execute(select(ThreatMatch).where(ThreatMatch.event_id == eid))
            for tm in tm_result.scalars().all():
                all_threat_matches.append({
                    "id": tm.id,
                    "ioc_value": tm.ioc_value,
                    "threat_category": tm.threat_category,
                    "severity_hint": tm.severity_hint,
                    "feed_id": tm.feed_id,
                    "first_seen": tm.first_seen.isoformat() + "Z" if tm.first_seen else None,
                })
            bf_result = await session.execute(select(BehavioralFlag).where(BehavioralFlag.event_id == eid))
            for bf in bf_result.scalars().all():
                all_behavioral_flags.append({
                    "id": bf.id,
                    "flag_type": bf.flag_type,
                    "details": bf.details,
                    "timestamp": bf.timestamp.isoformat() + "Z" if bf.timestamp else None,
                })

        # Look up investigation playbook based on alert classification
        classification = alert.classification or ""
        investigation_guide = PLAYBOOKS.get(classification)

        return {
            "alert": {
                "id": alert.id,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "severity": alert.severity,
                "classification": alert.classification,
                "escalate": alert.escalate,
                "confidence": alert.confidence,
                "threat_matches": alert.threat_matches,
                "behavioral_flags": alert.behavioral_flags,
                "llm_analysis": alert.llm_analysis,
                "status": getattr(alert, "status", "open"),
                "attack_technique": alert.attack_technique,
                "attack_tactic": alert.attack_tactic,
                "created_at": alert.created_at.isoformat() + "Z" if alert.created_at else None,
            },
            "investigation_guide": investigation_guide,
            "linked_events": linked_events,
            "event_threat_matches": all_threat_matches,
            "event_behavioral_flags": all_behavioral_flags,
        }

    @app.patch("/api/alerts/{alert_id}/status")
    async def update_alert_status(
        alert_id: int,
        body: dict,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Update alert status (open, false_positive, resolved, acknowledged)."""
        new_status = body.get("status", "")
        valid = {"open", "false_positive", "true_positive", "resolved", "acknowledged"}
        if new_status not in valid:
            raise HTTPException(400, f"Invalid status. Must be one of: {valid}")
        result = await session.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            raise HTTPException(404, "Alert not found")
        alert.status = new_status

        if new_status == "false_positive":
            detector = alert.classification or "unknown"
            if alert.behavioral_flags:
                try:
                    bf = json.loads(alert.behavioral_flags) if isinstance(alert.behavioral_flags, str) else alert.behavioral_flags
                    if isinstance(bf, list) and bf:
                        detector = bf[0].get("flag_type", detector)
                except Exception:
                    pass
            existing = await session.execute(
                select(FalsePositivePattern).where(
                    FalsePositivePattern.src_pattern == alert.src_ip,
                    FalsePositivePattern.dst_pattern == alert.dst_ip,
                    FalsePositivePattern.classification == (alert.classification or ""),
                )
            )
            if not existing.scalar_one_or_none():
                fp = FalsePositivePattern(
                    detector_name=detector,
                    src_pattern=alert.src_ip,
                    dst_pattern=alert.dst_ip,
                    domain_pattern=getattr(alert, "dst_domain", None),
                    classification=alert.classification or "",
                    reason=f"Auto-created from alert #{alert_id} marked FP",
                    created_by=user.username,
                )
                session.add(fp)

        # DGA feedback: label domain for classifier retraining
        _is_dga = alert.classification == "dga" or (
            alert.behavioral_flags and "dga_classifier" in str(alert.behavioral_flags)
        )
        _dga_domain = alert.dst_domain
        if not _dga_domain and _is_dga and alert.behavioral_flags:
            try:
                bf = json.loads(alert.behavioral_flags) if isinstance(alert.behavioral_flags, str) else alert.behavioral_flags
                for f in (bf if isinstance(bf, list) else []):
                    if f.get("flag_type") == "dga_classifier":
                        _dga_domain = f.get("details", {}).get("domain")
                        break
            except Exception:
                pass
        if _is_dga and _dga_domain:
            label = 0 if new_status == "false_positive" else 1
            existing_label = await session.execute(
                select(DGATrainingLabel).where(DGATrainingLabel.domain == _dga_domain)
            )
            if not existing_label.scalar_one_or_none():
                session.add(DGATrainingLabel(
                    domain=_dga_domain, label=label,
                    source="analyst",
                ))

        await session.commit()
        # Reload FP patterns in engine so it learns immediately
        engine = get_engine()
        await engine._load_false_positives()

        # Propagate FP/TP feedback to behavioral policies
        if new_status in ("false_positive", "true_positive") and alert.src_ip:
            await engine.propagate_policy_feedback(alert.src_ip, new_status)
        if _is_dga and _dga_domain:
            await engine._retrain_dga_with_labels()
        return {"id": alert_id, "status": new_status}

    # -----------------------------------------------------------------------
    # Threat intel endpoints
    # -----------------------------------------------------------------------

    @app.get("/api/threat-intel/status")
    async def threat_intel_status(
        user: User = Depends(require_analyst),
    ):
        """Get threat intelligence feed status."""
        engine = getattr(app.state, "engine", None)
        if engine and engine.feed_manager:
            feeds = engine.feed_manager.get_feed_status()
            return {
                "total_iocs": engine.feed_manager.total_ioc_count,
                "feeds": feeds,
                "feeds_loaded": sum(1 for f in feeds if f["status"] == "active"),
                "feeds_failed": sum(1 for f in feeds if f["status"] == "failed"),
                "feeds_total": len(feeds),
            }
        return {"total_iocs": 0, "feeds": [], "feeds_loaded": 0, "feeds_failed": 0, "feeds_total": 0}

    @app.post("/api/threat-intel/refresh")
    async def refresh_threat_intel(
        user: User = Depends(require_admin),
    ):
        """Force refresh all threat intelligence feeds (admin only)."""
        engine = getattr(app.state, "engine", None)
        if engine and engine.feed_manager:
            await engine.feed_manager.load_all_feeds()
            return {"status": "refreshed"}
        raise HTTPException(status_code=503, detail="Feed manager not available")

    # -----------------------------------------------------------------------
    # Network overview endpoints
    # -----------------------------------------------------------------------

    @app.get("/api/network/overview")
    async def network_overview(
        hours: int = Query(24, ge=1, le=168),
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Get network overview - active hosts, traffic volume, flags."""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Active source IPs with event counts
        result = await session.execute(
            select(SyslogEvent.source_ip, func.count(SyslogEvent.id).label("count"))
            .where(SyslogEvent.received_at >= since)
            .group_by(SyslogEvent.source_ip)
            .order_by(desc("count"))
        )
        active_hosts = [
            {"ip": row[0], "event_count": row[1]}
            for row in result
        ]

        # Flagged hosts
        flagged_result = await session.execute(
            select(Alert.src_ip, func.count(Alert.id).label("count"))
            .where(Alert.created_at >= since)
            .group_by(Alert.src_ip)
        )
        flagged_hosts = {row[0]: row[1] for row in flagged_result}

        # Event type breakdown
        type_result = await session.execute(
            select(SyslogEvent.event_type, func.count(SyslogEvent.id).label("count"))
            .where(SyslogEvent.received_at >= since)
            .group_by(SyslogEvent.event_type)
        )
        event_types = {row[0]: row[1] for row in type_result}

        return {
            "active_hosts": active_hosts,
            "flagged_hosts": [
                {"ip": ip, "alert_count": count}
                for ip, count in flagged_hosts.items()
            ],
            "event_type_breakdown": event_types,
            "period_hours": hours,
            "total_events": sum(h["event_count"] for h in active_hosts),
        }

    # -----------------------------------------------------------------------
    # Dashboard endpoints
    # -----------------------------------------------------------------------

    @app.get("/api/dashboard/summary")
    async def dashboard_summary(
        hours: int = Query(24, ge=1, le=168),
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Security posture overview — what's happening on your network."""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Fetch all recent alerts with enrichment data
        result = await session.execute(
            select(Alert).where(Alert.created_at >= since).order_by(desc(Alert.created_at))
        )
        alerts = result.scalars().all()

        # Severity breakdown
        severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for a in alerts:
            sev = a.severity or "info"
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

        # Top alert types
        classification_counts: dict = {}
        for a in alerts:
            cls = a.classification or "unknown"
            classification_counts[cls] = classification_counts.get(cls, 0) + 1
        top_alert_types = sorted(
            [{"classification": k, "count": v} for k, v in classification_counts.items()],
            key=lambda x: x["count"], reverse=True
        )[:10]

        # Extract enrichment from llm_analysis to build geo + destination data
        country_counts: dict = {}
        dst_ip_data: dict = {}  # {ip: {alert_count, country, org, classifications}}
        src_ip_counts: dict = {}
        src_ip_top_class: dict = {}
        iot_concerns = []

        _SAFE_COUNTRIES = {
            "United States", "Canada", "United Kingdom", "Germany", "France",
            "Netherlands", "Australia", "Japan", "Sweden", "Norway", "Denmark",
            "Finland", "Switzerland", "Ireland", "New Zealand", "Austria",
            "Belgium", "Luxembourg", "Iceland", "Singapore",
        }
        _PROXY_KEYWORDS = {"vpn", "proxy", "tunnel", "residential", "relay", "anonymiz"}

        engine = getattr(app.state, "engine", None)
        for a in alerts:
            # Track source IPs (internal talkers)
            if a.src_ip and a.src_ip.startswith(("10.", "172.", "192.168.")):
                src_ip_counts[a.src_ip] = src_ip_counts.get(a.src_ip, 0) + 1
                if a.src_ip not in src_ip_top_class:
                    src_ip_top_class[a.src_ip] = a.classification

            enrichment = {}
            if isinstance(a.llm_analysis, dict):
                enrichment = a.llm_analysis.get("enrichment", {})

            dst_ip = a.dst_ip or ""
            if not dst_ip or dst_ip.startswith(("10.", "172.", "192.168.", "127.")):
                continue
            if engine and dst_ip in engine._own_wan_ips:
                continue

            # Get geo data for this dst_ip from enrichment
            ip_info = enrichment.get(dst_ip, {})
            country = ip_info.get("country")
            country_code = ip_info.get("country_code")
            org = ip_info.get("org") or ip_info.get("isp") or ""
            asn = ip_info.get("asn", "")

            # Country counts
            if country:
                key = (country, country_code or "")
                country_counts[key] = country_counts.get(key, 0) + 1

            # Destination IP tracking
            if dst_ip not in dst_ip_data:
                dst_ip_data[dst_ip] = {
                    "ip": dst_ip, "alert_count": 0, "country": country,
                    "country_code": country_code, "org": org, "asn": asn,
                    "classifications": set(),
                }
            dst_ip_data[dst_ip]["alert_count"] += 1
            if a.classification:
                dst_ip_data[dst_ip]["classifications"].add(a.classification)

            # IoT concerns: internal IP -> suspicious destination
            is_suspicious_country = country and country not in _SAFE_COUNTRIES
            is_suspicious_org = any(kw in org.lower() for kw in _PROXY_KEYWORDS) if org else False
            if (is_suspicious_country or is_suspicious_org) and a.src_ip and a.src_ip.startswith(("10.", "172.", "192.168.")):
                iot_concerns.append({
                    "src_ip": a.src_ip,
                    "dst_ip": dst_ip,
                    "country": country,
                    "country_code": country_code,
                    "org": org,
                    "classification": a.classification,
                })

        # Format destination countries
        top_destination_countries = sorted(
            [{"country": k[0], "country_code": k[1], "alert_count": v}
             for k, v in country_counts.items()],
            key=lambda x: x["alert_count"], reverse=True
        )

        # Format suspicious destinations
        for d in dst_ip_data.values():
            d["classifications"] = list(d["classifications"])
        top_suspicious_destinations = sorted(
            dst_ip_data.values(), key=lambda x: x["alert_count"], reverse=True
        )[:20]

        # Format top talkers
        top_talkers = sorted(
            [{"ip": ip, "alert_count": cnt, "top_classification": src_ip_top_class.get(ip, "unknown")}
             for ip, cnt in src_ip_counts.items()],
            key=lambda x: x["alert_count"], reverse=True
        )[:10]

        # Deduplicate IoT concerns by (src_ip, dst_ip)
        seen_iot = set()
        deduped_iot = []
        for item in iot_concerns:
            key = (item["src_ip"], item["dst_ip"])
            if key not in seen_iot:
                seen_iot.add(key)
                item["count"] = sum(1 for i in iot_concerns if (i["src_ip"], i["dst_ip"]) == key)
                deduped_iot.append(item)
        deduped_iot.sort(key=lambda x: x["count"], reverse=True)

        # Threat intel + ingestion status
        engine = getattr(app.state, "engine", None)
        threat_intel_status = {"feeds_loaded": 0, "total_iocs": 0}
        ingestion_status = {"events_24h": 0, "syslog_active": False}
        if engine:
            if engine.feed_manager:
                feeds = engine.feed_manager.get_feed_status()
                threat_intel_status = {
                    "feeds_loaded": sum(1 for f in feeds if f["status"] == "active"),
                    "total_iocs": engine.feed_manager.total_ioc_count,
                }
            if engine.syslog_listener:
                ingestion_status["syslog_active"] = engine.syslog_listener.is_running
            event_count_result = await session.execute(
                select(func.count(SyslogEvent.id)).where(SyslogEvent.received_at >= since)
            )
            ingestion_status["events_24h"] = event_count_result.scalar() or 0

        # Alert timeline — bucket by hour for sparkline
        now_utc = datetime.now(timezone.utc)
        timeline_buckets: dict[str, dict[str, int]] = {}
        for h in range(hours):
            bucket_time = now_utc - timedelta(hours=h)
            key = bucket_time.strftime("%Y-%m-%dT%H:00:00Z")
            timeline_buckets[key] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in alerts:
            if a.created_at:
                bucket_key = a.created_at.strftime("%Y-%m-%dT%H:00:00Z")
                if bucket_key in timeline_buckets:
                    sev = a.severity or "low"
                    timeline_buckets[bucket_key][sev] = timeline_buckets[bucket_key].get(sev, 0) + 1
        alert_timeline = sorted(
            [{"hour": k, **v, "total": sum(v.values())} for k, v in timeline_buckets.items()],
            key=lambda x: x["hour"]
        )

        # Recent critical/high alerts for quick triage
        recent_critical = []
        for a in alerts:
            if a.severity in ("critical", "high") and len(recent_critical) < 5:
                enrichment = {}
                if isinstance(a.llm_analysis, dict):
                    enrichment = a.llm_analysis.get("enrichment", {})
                dst_info = enrichment.get(a.dst_ip or "", {})
                recent_critical.append({
                    "id": a.id,
                    "severity": a.severity,
                    "classification": a.classification,
                    "src_ip": a.src_ip,
                    "dst_ip": a.dst_ip,
                    "dst_country": dst_info.get("country"),
                    "dst_org": dst_info.get("org"),
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                    "status": a.status,
                })

        # Previous period for trend comparison (same window length, immediately prior)
        prev_since = since - timedelta(hours=hours)
        prev_result = await session.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.created_at >= prev_since, Alert.created_at < since)
            .group_by(Alert.severity)
        )
        prev_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        prev_total = 0
        for sev, cnt in prev_result.all():
            prev_breakdown[sev or "info"] = cnt
            prev_total += cnt

        return {
            "total_alerts_24h": len(alerts),
            "severity_breakdown": severity_breakdown,
            "prev_total_alerts": prev_total,
            "prev_severity_breakdown": prev_breakdown,
            "top_alert_types": top_alert_types,
            "top_destination_countries": top_destination_countries,
            "top_suspicious_destinations": top_suspicious_destinations,
            "top_talkers": top_talkers,
            "iot_concerns": deduped_iot[:20],
            "threat_intel_status": threat_intel_status,
            "ingestion_status": ingestion_status,
            "alert_timeline": alert_timeline,
            "recent_critical": recent_critical,
            "period_hours": hours,
        }

    @app.get("/api/dashboard/geo-breakdown")
    async def dashboard_geo_breakdown(
        hours: int = Query(24, ge=1, le=168),
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Country breakdown of alert destinations."""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)

        result = await session.execute(
            select(Alert).where(Alert.created_at >= since)
        )
        alerts = result.scalars().all()

        country_data: dict = {}
        for a in alerts:
            enrichment = {}
            if isinstance(a.llm_analysis, dict):
                enrichment = a.llm_analysis.get("enrichment", {})

            dst_ip = a.dst_ip or ""
            if not dst_ip or dst_ip.startswith(("10.", "172.", "192.168.", "127.")):
                continue

            ip_info = enrichment.get(dst_ip, {})
            country = ip_info.get("country")
            code = ip_info.get("country_code", "")
            if not country:
                continue

            if country not in country_data:
                country_data[country] = {"country": country, "code": code, "alert_count": 0, "unique_ips": set()}
            country_data[country]["alert_count"] += 1
            country_data[country]["unique_ips"].add(dst_ip)

        countries = sorted(
            [{"country": v["country"], "code": v["code"], "alert_count": v["alert_count"],
              "unique_ips": len(v["unique_ips"])}
             for v in country_data.values()],
            key=lambda x: x["alert_count"], reverse=True
        )

        return {"countries": countries, "period_hours": hours}

    @app.get("/api/dashboard/device-activity")
    async def dashboard_device_activity(
        hours: int = Query(24, ge=1, le=168),
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Per-device activity — which internal hosts are generating alerts."""
        since = datetime.now(timezone.utc) - timedelta(hours=hours)

        result = await session.execute(
            select(Alert).where(Alert.created_at >= since).order_by(desc(Alert.created_at))
        )
        alerts = result.scalars().all()

        devices: dict = {}
        for a in alerts:
            src = a.src_ip or ""
            if not src.startswith(("10.", "172.", "192.168.")):
                continue

            if src not in devices:
                devices[src] = {
                    "ip": src,
                    "alert_count": 0,
                    "destinations": {},
                    "classifications": set(),
                    "last_alert": None,
                }
            dev = devices[src]
            dev["alert_count"] += 1
            if a.classification:
                dev["classifications"].add(a.classification)
            if dev["last_alert"] is None and a.created_at:
                dev["last_alert"] = a.created_at.isoformat() + "Z"

            dst_ip = a.dst_ip or ""
            if dst_ip and not dst_ip.startswith(("10.", "172.", "192.168.", "127.")):
                enrichment = {}
                if isinstance(a.llm_analysis, dict):
                    enrichment = a.llm_analysis.get("enrichment", {})
                ip_info = enrichment.get(dst_ip, {})
                if dst_ip not in dev["destinations"]:
                    dev["destinations"][dst_ip] = {
                        "ip": dst_ip,
                        "country": ip_info.get("country"),
                        "org": ip_info.get("org") or ip_info.get("isp"),
                    }

        device_list = []
        for dev in sorted(devices.values(), key=lambda x: x["alert_count"], reverse=True):
            top_dests = sorted(dev["destinations"].values(), key=lambda x: x.get("country") or "", reverse=True)[:5]
            device_list.append({
                "ip": dev["ip"],
                "alert_count": dev["alert_count"],
                "unique_destinations": len(dev["destinations"]),
                "top_destinations": top_dests,
                "classifications": list(dev["classifications"]),
                "last_alert": dev["last_alert"],
            })

        return {"devices": device_list, "period_hours": hours}

    # -----------------------------------------------------------------------
    # Host risk score endpoint
    # -----------------------------------------------------------------------

    @app.get("/api/dashboard/host-risk")
    async def host_risk_scores(
        hours: int = Query(24, ge=1, le=168),
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Composite risk score per internal host based on recent alert history.

        Severity weights: critical=25, high=15, medium=5, low=1.
        Score capped at 100.
        """
        since = datetime.now(timezone.utc) - timedelta(hours=hours)

        result = await session.execute(
            select(Alert).where(Alert.created_at >= since)
        )
        alerts = result.scalars().all()

        severity_weights = {"critical": 25, "high": 15, "medium": 5, "low": 1, "info": 0}

        host_data: dict = {}
        for a in alerts:
            src = a.src_ip or ""
            if not is_internal(src):
                continue

            if src not in host_data:
                host_data[src] = {
                    "ip": src,
                    "raw_score": 0,
                    "alert_count": 0,
                    "top_severity": "info",
                    "top_classification": None,
                    "severities": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                }
            hd = host_data[src]
            sev = a.severity or "info"
            hd["raw_score"] += severity_weights.get(sev, 0)
            hd["alert_count"] += 1
            hd["severities"][sev] = hd["severities"].get(sev, 0) + 1

            # Track top severity
            sev_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
            if sev_rank.get(sev, 0) > sev_rank.get(hd["top_severity"], 0):
                hd["top_severity"] = sev
            if hd["top_classification"] is None and a.classification:
                hd["top_classification"] = a.classification

        scores = []
        for hd in host_data.values():
            scores.append({
                "ip": hd["ip"],
                "risk_score": min(hd["raw_score"], 100),
                "alert_count": hd["alert_count"],
                "top_severity": hd["top_severity"],
                "top_classification": hd["top_classification"] or "unknown",
            })

        scores.sort(key=lambda x: x["risk_score"], reverse=True)

        return {"hosts": scores, "period_hours": hours}

    # -----------------------------------------------------------------------
    # Anomaly detection endpoint
    # -----------------------------------------------------------------------

    @app.get("/api/analytics/anomalies")
    async def get_anomalies(
        user: User = Depends(require_analyst),
    ):
        """Return the latest IsolationForest anomaly detection results."""
        engine = getattr(app.state, "engine", None)
        if not engine:
            return {"anomalies": [], "last_run": None}

        detector = getattr(engine, "anomaly_detector", None)
        if not detector:
            return {"anomalies": [], "last_run": None}

        # Filter out suppressed (ip, detector_name) pairs
        suppressions = getattr(engine, '_anomaly_suppressions', set())
        results = detector.last_results
        if suppressions and results:
            results = [
                r for r in results
                if (r.ip if hasattr(r, 'ip') else r.get('ip', ''),
                    r.detector_name if hasattr(r, 'detector_name') else r.get('detector_name', ''))
                not in suppressions
            ]

        return {
            "anomalies": results,
            "last_run": detector.last_run.isoformat() if detector.last_run else None,
        }

    @app.post("/api/analytics/anomalies/suppress")
    async def suppress_anomaly(
        body: SuppressionRequest,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Suppress anomaly results for a given IP and detector name."""
        engine = getattr(app.state, "engine", None)

        # Check for existing suppression
        result = await session.execute(
            select(AnomalySuppression).where(
                AnomalySuppression.ip == body.ip,
                AnomalySuppression.detector_name == body.detector_name,
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            return {"status": "already_suppressed", "ip": body.ip, "detector_name": body.detector_name}

        suppression = AnomalySuppression(
            ip=body.ip,
            detector_name=body.detector_name,
            created_by=user.username,
        )
        session.add(suppression)
        await session.commit()

        # Add to in-memory set
        if engine:
            engine._anomaly_suppressions.add((body.ip, body.detector_name))

        logger.info("Anomaly suppression added", extra={
            "extra_data": {"ip": body.ip, "detector_name": body.detector_name, "created_by": user.username}
        })
        return {"status": "suppressed", "ip": body.ip, "detector_name": body.detector_name}

    @app.get("/api/analytics/anomalies/suppressions")
    async def get_suppressions(
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Return all anomaly suppressions."""
        result = await session.execute(select(AnomalySuppression).order_by(AnomalySuppression.created_at.desc()))
        rows = result.scalars().all()
        return [
            {
                "id": s.id,
                "ip": s.ip,
                "detector_name": s.detector_name,
                "created_at": s.created_at.isoformat() + "Z" if s.created_at else None,
                "created_by": s.created_by,
            }
            for s in rows
        ]

    @app.delete("/api/analytics/anomalies/suppress")
    async def delete_suppression(
        body: SuppressionRequest,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Remove an anomaly suppression."""
        engine = getattr(app.state, "engine", None)

        result = await session.execute(
            select(AnomalySuppression).where(
                AnomalySuppression.ip == body.ip,
                AnomalySuppression.detector_name == body.detector_name,
            )
        )
        suppression = result.scalar_one_or_none()
        if not suppression:
            raise HTTPException(404, "Suppression not found")

        await session.delete(suppression)
        await session.commit()

        # Remove from in-memory set
        if engine:
            engine._anomaly_suppressions.discard((body.ip, body.detector_name))

        logger.info("Anomaly suppression removed", extra={
            "extra_data": {"ip": body.ip, "detector_name": body.detector_name, "removed_by": user.username}
        })
        return {"status": "removed", "ip": body.ip, "detector_name": body.detector_name}

    @app.get("/api/analytics/ensemble")
    async def get_ensemble_scores(
        user: User = Depends(require_analyst),
    ):
        """Return multi-model ensemble scoring results."""
        engine = getattr(app.state, "engine", None)
        if not engine or not engine.ensemble:
            return {"hosts": [], "last_run": None, "detectors_run": 0}

        results = engine.ensemble.last_results
        return {
            "hosts": results,
            "last_run": engine.ensemble.last_run.isoformat() if engine.ensemble.last_run else None,
            "detectors_run": len(engine.ensemble.detectors),
        }

    # -----------------------------------------------------------------------
    # Configuration endpoints
    # -----------------------------------------------------------------------

    @app.get("/api/config")
    async def get_configuration(
        user: User = Depends(require_admin),
    ):
        """Get current configuration."""
        config = get_config()
        return {
            "feeds": {
                "refresh_interval_seconds": config.feeds.refresh_interval_seconds,
                "urls": config.feeds.urls,
            },
            "analytics": {
                "thresholds": {
                    "outbound_volume_bytes_per_minute": config.analytics.thresholds.outbound_volume_bytes_per_minute,
                    "high_entropy_shannon_threshold": config.analytics.thresholds.high_entropy_shannon_threshold,
                    "blocked_query_repeat_threshold": config.analytics.thresholds.blocked_query_repeat_threshold,
                    "port_scan_distinct_ports": config.analytics.thresholds.port_scan_distinct_ports,
                    "beaconing_interval_tolerance_seconds": config.analytics.thresholds.beaconing_interval_tolerance_seconds,
                    "beaconing_min_repetitions": config.analytics.thresholds.beaconing_min_repetitions,
                },
                "baseline_window_days": config.analytics.baseline_window_days,
                "cooldown": config.analytics.cooldown,
            },
            "llm": {
                "enabled": config.llm.enabled,
                "provider": config.llm.provider,
                "model": config.llm.model,
                "effort": config.llm.effort,
                "base_url": config.llm.base_url,
                "temperature": config.llm.temperature,
                "max_tokens": config.llm.max_tokens,
                "fallback_provider": config.llm.fallback_provider,
                "fallback_model": config.llm.fallback_model,
                "fallback_base_url": config.llm.fallback_base_url,
            },
            "listeners": {
                "syslog_port": config.listeners.syslog_port,
                "api_port": config.listeners.api_port,
            },
            # Read-only: topology comes from config.yaml / UEBA_* env vars, so
            # what you see here is exactly what the detectors are using.
            "network": {
                "name": config.network.name,
                "lan_cidrs": config.network.lan_cidrs,
                "gateway_ips": config.network.gateway_ips,
                "dns_servers": config.network.dns_servers,
                "infra_hosts": config.network.infra_hosts,
                "own_hostnames": config.network.own_hostnames,
                "reputable_orgs": config.network.reputable_orgs,
            },
        }

    @app.put("/api/config")
    async def update_configuration(
        body: dict = Body(...),
        user: User = Depends(require_admin),
    ):
        """Update configuration (admin only). Note: changes require restart for some values."""
        # This updates the in-memory config; persistent changes require config.yaml
        config = get_config()
        if "feeds" in body:
            fd = body["feeds"]
            if "refresh_interval_seconds" in fd:
                config.feeds.refresh_interval_seconds = fd["refresh_interval_seconds"]
        if "analytics" in body:
            ad = body["analytics"]
            if "thresholds" in ad:
                t = ad["thresholds"]
                thresholds = config.analytics.thresholds
                for key in ["outbound_volume_bytes_per_minute", "high_entropy_shannon_threshold",
                           "blocked_query_repeat_threshold", "port_scan_distinct_ports",
                           "beaconing_interval_tolerance_seconds", "beaconing_min_repetitions"]:
                    if key in t:
                        setattr(thresholds, key, t[key])
            if "cooldown" in ad:
                config.analytics.cooldown.update(ad["cooldown"])
        if "llm" in body:
            ld = body["llm"]
            llm = config.llm
            for key in ("provider", "model", "base_url", "temperature", "max_tokens",
                       "fallback_provider", "fallback_model", "fallback_base_url"):
                if key in ld:
                    setattr(llm, key, ld[key])
            if "api_key" in ld:
                llm.api_key = ld["api_key"]
            if "fallback_api_key" in ld:
                llm.fallback_api_key = ld["fallback_api_key"]
        if "shadow_mode" in body:
            engine = getattr(app.state, "engine", None)
            if engine:
                if not hasattr(engine, "_shadow_mode"):
                    engine._shadow_mode = {}
                for detector_name, enabled in body["shadow_mode"].items():
                    engine._shadow_mode[detector_name] = bool(enabled)
        return {"status": "updated"}

    # -----------------------------------------------------------------------
    # Interactive LLM Chat
    # -----------------------------------------------------------------------

    @app.post("/api/chat")
    async def chat_endpoint(
        body: ChatRequest,
        user: User = Depends(require_analyst),
    ):
        """Interactive AI chat endpoint with SSE streaming.

        Accepts a message and optional alert_id for context.  Returns a
        Server-Sent Events stream with LLM responses.  Rate limited
        to 10 queries per minute per user.
        """
        if not _check_rate_limit(str(user.id)):
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Max 10 queries per minute.",
            )

        async def event_stream():
            async for chunk in stream_chat(body.message, body.alert_id, str(user.id)):
                yield chunk

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    # -----------------------------------------------------------------------
    # Feature 8: False Positive Pattern CRUD
    # -----------------------------------------------------------------------

    @app.get("/api/fp-patterns")
    async def list_fp_patterns(
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """List all false positive patterns, ordered by times_matched desc."""
        result = await session.execute(
            select(FalsePositivePattern).order_by(FalsePositivePattern.times_matched.desc())
        )
        patterns = result.scalars().all()
        return [
            {
                "id": p.id,
                "detector_name": p.detector_name,
                "src_pattern": p.src_pattern,
                "dst_pattern": p.dst_pattern,
                "domain_pattern": p.domain_pattern,
                "classification": p.classification,
                "reason": p.reason,
                "times_matched": p.times_matched,
                "created_at": p.created_at.isoformat() + "Z" if p.created_at else None,
                "created_by": p.created_by,
            }
            for p in patterns
        ]

    @app.post("/api/fp-patterns")
    async def create_fp_pattern(
        body: FpPatternCreate,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Create a new false positive pattern."""
        pattern = FalsePositivePattern(
            detector_name=body.detector_name,
            src_pattern=body.src_pattern,
            dst_pattern=body.dst_pattern,
            domain_pattern=body.domain_pattern,
            classification=body.classification,
            reason=body.reason,
            created_by=user.username,
        )
        session.add(pattern)
        await session.commit()
        await session.refresh(pattern)

        # Reload FP patterns in engine
        engine = get_engine()
        await engine._load_false_positives()

        return {
            "id": pattern.id,
            "detector_name": pattern.detector_name,
            "src_pattern": pattern.src_pattern,
            "dst_pattern": pattern.dst_pattern,
            "domain_pattern": pattern.domain_pattern,
            "classification": pattern.classification,
            "reason": pattern.reason,
            "times_matched": pattern.times_matched,
            "created_at": pattern.created_at.isoformat() + "Z" if pattern.created_at else None,
            "created_by": pattern.created_by,
        }

    @app.delete("/api/fp-patterns/{pattern_id}")
    async def delete_fp_pattern(
        pattern_id: int,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Delete a false positive pattern."""
        result = await session.execute(
            select(FalsePositivePattern).where(FalsePositivePattern.id == pattern_id)
        )
        pattern = result.scalar_one_or_none()
        if not pattern:
            raise HTTPException(404, "Pattern not found")

        await session.delete(pattern)
        await session.commit()

        # Reload FP patterns in engine
        engine = get_engine()
        await engine._load_false_positives()

        return {"status": "deleted", "id": pattern_id}

    # -----------------------------------------------------------------------
    # Feature 10: Shadow Results
    # -----------------------------------------------------------------------

    @app.get("/api/analytics/shadow-results")
    async def get_shadow_results(
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Get shadow mode detection results (what would have alerted)."""
        result = await session.execute(
            select(ShadowResult).order_by(ShadowResult.created_at.desc()).limit(100)
        )
        rows = result.scalars().all()
        return [
            {
                "id": r.id,
                "detector_name": r.detector_name,
                "ip": r.ip,
                "score": r.score,
                "details": r.details,
                "created_at": r.created_at.isoformat() + "Z" if r.created_at else None,
            }
            for r in rows
        ]

    # -----------------------------------------------------------------------
    # Feature 11: Related Alerts
    # -----------------------------------------------------------------------

    @app.get("/api/alerts/{alert_id}/related")
    async def get_related_alerts(
        alert_id: int,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Get alerts related to this one by src_ip or dst_ip within +/- 1 hour."""
        result = await session.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            raise HTTPException(404, "Alert not found")

        # Build alert response
        alert_data = {
            "id": alert.id,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "severity": alert.severity,
            "classification": alert.classification,
            "escalate": alert.escalate,
            "confidence": alert.confidence,
            "attack_technique": alert.attack_technique,
            "attack_tactic": alert.attack_tactic,
            "created_at": alert.created_at.isoformat() + "Z" if alert.created_at else None,
        }

        src_ip = alert.src_ip
        dst_ip = alert.dst_ip
        created_at = alert.created_at

        if not created_at:
            return {"alert": alert_data, "related": [], "timeline_groups": {}}

        window_start = created_at - timedelta(hours=1)
        window_end = created_at + timedelta(hours=1)

        # Query related alerts: same src_ip or dst_ip within time window, excluding self
        related_query = select(Alert).where(
            Alert.id != alert_id,
            Alert.created_at >= window_start,
            Alert.created_at <= window_end,
        )
        if src_ip and dst_ip:
            related_query = related_query.where(
                (Alert.src_ip == src_ip) | (Alert.dst_ip == dst_ip) |
                (Alert.src_ip == dst_ip) | (Alert.dst_ip == src_ip)
            )
        elif src_ip:
            related_query = related_query.where(
                (Alert.src_ip == src_ip) | (Alert.dst_ip == src_ip)
            )
        elif dst_ip:
            related_query = related_query.where(
                (Alert.src_ip == dst_ip) | (Alert.dst_ip == dst_ip)
            )
        related_query = related_query.order_by(Alert.created_at)

        related_result = await session.execute(related_query)
        related_rows = related_result.scalars().all()

        related = [
            {
                "id": r.id,
                "src_ip": r.src_ip,
                "dst_ip": r.dst_ip,
                "severity": r.severity,
                "classification": r.classification,
                "created_at": r.created_at.isoformat() + "Z" if r.created_at else None,
                "attack_technique": r.attack_technique,
                "attack_tactic": r.attack_tactic,
            }
            for r in related_rows
        ]

        # Group by mitre_tactic for timeline display
        timeline_groups: dict = {}
        for r in related_rows:
            tactic = r.attack_tactic or "Unknown"
            if tactic not in timeline_groups:
                timeline_groups[tactic] = []
            timeline_groups[tactic].append(r.id)

        return {
            "alert": alert_data,
            "related": related,
            "timeline_groups": timeline_groups,
        }

    # -----------------------------------------------------------------------
    # Feature 14: MITRE ATT&CK Coverage
    # -----------------------------------------------------------------------

    @app.get("/api/analytics/coverage")
    async def get_mitre_coverage(
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Get MITRE ATT&CK coverage from alerts in last 30 days."""
        since = datetime.now(timezone.utc) - timedelta(days=30)

        # Query alerts grouped by technique
        result = await session.execute(
            select(Alert.attack_technique, func.count(Alert.id).label("cnt"))
            .where(Alert.created_at >= since, Alert.attack_technique.isnot(None))
            .group_by(Alert.attack_technique)
            .order_by(desc("cnt"))
        )
        technique_counts = {row.attack_technique: row.cnt for row in result.all()}

        # Build technique list with detector mappings
        # Invert MITRE_MAPPING: technique -> list of detectors
        technique_detectors: dict = {}
        for flag_type, (technique_id, tactic) in MITRE_MAPPING.items():
            if technique_id not in technique_detectors:
                technique_detectors[technique_id] = {
                    "technique_id": technique_id,
                    "tactic": tactic,
                    "detectors": [],
                }
            technique_detectors[technique_id]["detectors"].append(flag_type)

        techniques = []
        for tid, info in technique_detectors.items():
            techniques.append({
                "technique_id": tid,
                "tactic": info["tactic"],
                "count": technique_counts.get(tid, 0),
                "covered_by_detectors": info["detectors"],
            })

        # Sort by count desc
        techniques.sort(key=lambda t: t["count"], reverse=True)

        return {
            "techniques": techniques,
            "period_days": 30,
        }

    # -----------------------------------------------------------------------
    # Feature 15: Rule Test Mode
    # -----------------------------------------------------------------------

    @app.post("/api/rules/test")
    async def test_rule(
        body: RuleTestRequest,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Test a custom rule against the last 1000 events without creating alerts."""
        # Validate rule_json
        try:
            rule_json = json.loads(body.rule_json)
        except json.JSONDecodeError:
            raise HTTPException(400, "rule_json must be valid JSON")

        valid_severities = {"critical", "high", "medium", "low", "info"}
        if body.severity not in valid_severities:
            raise HTTPException(400, f"Invalid severity. Must be one of: {valid_severities}")

        # Get last 1000 events
        events_result = await session.execute(
            select(SyslogEvent).order_by(SyslogEvent.id.desc()).limit(1000)
        )
        events = events_result.scalars().all()

        engine = get_engine()
        if not engine:
            raise HTTPException(503, "Engine not available")

        # Build a temporary rule list for evaluate_rules
        temp_rule = {
            "id": 0,
            "name": body.name,
            "rule_json": rule_json,
            "severity": body.severity,
        }

        # Save original custom rules and replace with test rule
        original_rules = engine._custom_rules
        engine._custom_rules = [temp_rule]

        try:
            matches = []
            for ev in events:
                event_data = {
                    "source_ip": ev.source_ip,
                    "event_type": ev.event_type,
                    "parsed_fields": ev.parsed_fields or {},
                    "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                }
                # Run rule evaluation with empty enrichment
                rule_matches = engine.evaluate_rules(event_data, {})
                if rule_matches:
                    parsed = ev.parsed_fields or {}
                    src_ip = parsed.get("src_ip") or parsed.get("client_ip") or ev.source_ip
                    dst_ip = parsed.get("dst_ip", "")
                    for m in rule_matches:
                        matches.append({
                            "event_id": ev.id,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "match_detail": m,
                        })
        finally:
            # Restore original rules
            engine._custom_rules = original_rules

        return {
            "would_generate_alerts": len(matches),
            "sample_matches": matches[:20],  # Cap at 20 samples
            "total_events_tested": len(events),
        }

    # -----------------------------------------------------------------------
    # Feature 18: Device Roles CRUD
    # -----------------------------------------------------------------------

    @app.get("/api/devices/roles")
    async def list_device_roles(
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """List all device roles."""
        result = await session.execute(select(DeviceRole).order_by(DeviceRole.ip))
        roles = result.scalars().all()
        return [
            {
                "id": r.id,
                "ip": r.ip,
                "role": r.role,
                "label": r.label,
                "created_at": r.created_at.isoformat() + "Z" if r.created_at else None,
            }
            for r in roles
        ]

    @app.post("/api/devices/roles")
    async def create_device_role(
        body: DeviceRoleCreate,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_admin),
    ):
        """Create a new device role (admin only)."""
        # Check for duplicate IP
        existing = await session.execute(
            select(DeviceRole).where(DeviceRole.ip == body.ip)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(409, "Device role already exists for this IP")

        role = DeviceRole(
            ip=body.ip,
            role=body.role,
            label=body.label,
        )
        session.add(role)
        await session.commit()
        await session.refresh(role)

        return {
            "id": role.id,
            "ip": role.ip,
            "role": role.role,
            "label": role.label,
            "created_at": role.created_at.isoformat() + "Z" if role.created_at else None,
        }

    @app.put("/api/devices/roles/{role_id}")
    async def update_device_role(
        role_id: int,
        body: DeviceRoleUpdate,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_admin),
    ):
        """Update a device role (admin only)."""
        result = await session.execute(select(DeviceRole).where(DeviceRole.id == role_id))
        role = result.scalar_one_or_none()
        if not role:
            raise HTTPException(404, "Device role not found")

        if body.role is not None:
            role.role = body.role
        if body.label is not None:
            role.label = body.label

        await session.commit()
        await session.refresh(role)

        return {
            "id": role.id,
            "ip": role.ip,
            "role": role.role,
            "label": role.label,
            "created_at": role.created_at.isoformat() + "Z" if role.created_at else None,
        }

    @app.delete("/api/devices/roles/{role_id}")
    async def delete_device_role(
        role_id: int,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_admin),
    ):
        """Delete a device role (admin only)."""
        result = await session.execute(select(DeviceRole).where(DeviceRole.id == role_id))
        role = result.scalar_one_or_none()
        if not role:
            raise HTTPException(404, "Device role not found")

        await session.delete(role)
        await session.commit()

        return {"status": "deleted", "id": role_id}

    # -----------------------------------------------------------------------
    # Feature 20: Model History
    # -----------------------------------------------------------------------

    @app.get("/api/analytics/model-history")
    async def get_model_history(
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_analyst),
    ):
        """Get anomaly detector model training history."""
        result = await session.execute(
            select(ModelRun).order_by(ModelRun.trained_at.desc())
        )
        runs = result.scalars().all()
        return [
            {
                "id": r.id,
                "detector_name": r.detector_name,
                "data_hash": r.data_hash,
                "trained_at": r.trained_at.isoformat() + "Z" if r.trained_at else None,
                "training_time_ms": r.training_time_ms,
                "sample_count": r.sample_count,
                "anomaly_count": r.anomaly_count,
                "score_stats": r.score_stats_json,
            }
            for r in runs
        ]

    # -----------------------------------------------------------------------
    # Feature 21: Rule Maturity
    # -----------------------------------------------------------------------

    @app.patch("/api/rules/{rule_id}/promote")
    async def promote_rule(
        rule_id: int,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_admin),
    ):
        """Promote a rule: experimental -> active, active -> stable (admin only)."""
        result = await session.execute(select(CustomRule).where(CustomRule.id == rule_id))
        rule = result.scalar_one_or_none()
        if not rule:
            raise HTTPException(404, "Rule not found")

        maturity = getattr(rule, "maturity_status", "active")
        if maturity == "experimental":
            rule.maturity_status = "active"
        elif maturity == "active":
            rule.maturity_status = "stable"
        elif maturity == "stable":
            raise HTTPException(400, "Rule is already at maximum maturity (stable)")
        elif maturity == "deprecated":
            raise HTTPException(400, "Cannot promote a deprecated rule")
        else:
            raise HTTPException(400, f"Unknown maturity status: {maturity}")

        rule.updated_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(rule)

        # Reload rules in engine
        engine = get_engine()
        await engine.reload_rules()

        return {
            "id": rule.id,
            "name": rule.name,
            "maturity_status": rule.maturity_status,
            "previous_maturity": maturity,
        }

    @app.patch("/api/rules/{rule_id}/deprecate")
    async def deprecate_rule(
        rule_id: int,
        body: RuleDeprecateRequest,
        session: AsyncSession = Depends(get_session),
        user: User = Depends(require_admin),
    ):
        """Deprecate a rule: set maturity_status='deprecated', disabled=True (admin only)."""
        result = await session.execute(select(CustomRule).where(CustomRule.id == rule_id))
        rule = result.scalar_one_or_none()
        if not rule:
            raise HTTPException(404, "Rule not found")

        rule.maturity_status = "deprecated"
        rule.deprecation_reason = body.reason
        rule.enabled = False
        rule.updated_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(rule)

        # Reload rules in engine
        engine = get_engine()
        await engine.reload_rules()

        return {
            "id": rule.id,
            "name": rule.name,
            "maturity_status": rule.maturity_status,
            "deprecation_reason": rule.deprecation_reason,
            "enabled": rule.enabled,
        }

    # -----------------------------------------------------------------------
    # WebSocket endpoint for live event feed
    # -----------------------------------------------------------------------

    @app.websocket("/ws/events")
    async def websocket_events(websocket: WebSocket):
        """WebSocket endpoint for live event streaming."""
        engine = getattr(app.state, "engine", None)
        if not engine or not engine.websocket:
            await websocket.close(code=1011, reason="WebSocket manager not available")
            return

        ws_manager = engine.websocket
        await ws_manager.connect(websocket)
        try:
            while True:
                # Keep connection alive, handle pings
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_text("pong")
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            await ws_manager.disconnect(websocket)

    return app


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    """Entry point for uvicorn or direct execution."""
    import uvicorn

    config = get_config()
    setup_logging(config.logging.level)

    logger.info("Starting UEBA Platform server", extra={
        "extra_data": {
            "host": config.listeners.api_host,
            "port": config.listeners.api_port,
        }
    })

    app = create_app()

    uvicorn.run(
        app,
        host=config.listeners.api_host,
        port=config.listeners.api_port,
        log_level="info",
        log_config=None,  # Use our own logging config
    )


app = create_app()

if __name__ == "__main__":
    main()
