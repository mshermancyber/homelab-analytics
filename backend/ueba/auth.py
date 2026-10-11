"""Authentication and authorization - JWT sessions with RBAC.

Roles: admin, analyst, viewer
- Admin: Full access to all dashboard views, configuration, and system management
- Analyst: View alerts, event feed, threat intel status, network overview; cannot modify config
- Viewer: Read-only access to dashboard views
"""
import os
from datetime import datetime, timezone, timedelta
from secrets import token_urlsafe
from typing import Optional

import bcrypt
from jose import jwt, JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ueba.credentials import get_secret
from ueba.logging_config import get_logger
from ueba.models import User

logger = get_logger(__name__)

def _resolve_jwt_secret() -> str:
    """Resolve the JWT signing secret.

    Set ``JWT_SECRET`` (env or ``.env``) to a long random string — e.g.
    ``openssl rand -hex 32``.  Without it a random per-process secret is used,
    which is safe but invalidates every session on restart, so the server logs
    a loud warning instead of shipping a predictable default.
    """
    secret = get_secret("JWT_SECRET")
    if secret:
        return secret
    logger.warning(
        "JWT_SECRET is not set — generating an ephemeral secret. "
        "All sessions will be invalidated on restart. Set JWT_SECRET in .env."
    )
    return token_urlsafe(64)


JWT_SECRET = _resolve_jwt_secret()
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = int(os.environ.get("JWT_EXPIRATION_HOURS", "24"))

# Validate JWT algorithm at module load time — reject weak or "none" algorithms
_STRONG_ALGORITHMS = {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
if JWT_ALGORITHM.lower() == "none" or JWT_ALGORITHM not in _STRONG_ALGORITHMS:
    raise ValueError(
        f"JWT_ALGORITHM '{JWT_ALGORITHM}' is not secure. "
        f"Must be one of: {', '.join(sorted(_STRONG_ALGORITHMS))}"
    )

# Permission matrix
ROLE_PERMISSIONS = {
    "admin": {
        "view_dashboard", "view_alerts", "view_event_feed", "view_threat_intel",
        "view_network_overview", "view_top_offenders", "view_event_detail",
        "manage_config", "manage_users", "manage_feeds",
    },
    "analyst": {
        "view_dashboard", "view_alerts", "view_event_feed", "view_threat_intel",
        "view_network_overview", "view_top_offenders", "view_event_detail",
    },
    "viewer": {
        "view_dashboard", "view_alerts", "view_event_feed", "view_threat_intel",
        "view_network_overview", "view_top_offenders",
    },
}


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
    except (ValueError, TypeError):
        return False


def create_access_token(username: str, role: str, user_id: int) -> str:
    """Create a JWT access token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "user_id": user_id,
        "role": role,
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRATION_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT token. Returns payload or None."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError as e:
        logger.debug("JWT decode failed", extra={"extra_data": {"error": str(e)}})
        return None


def has_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific permission."""
    permissions = ROLE_PERMISSIONS.get(role, set())
    return permission in permissions


async def authenticate_user(session: AsyncSession, username: str, password: str) -> Optional[User]:
    """Authenticate a user by username and password."""
    result = await session.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user and verify_password(password, user.password_hash):
        return user
    return None


async def create_user(session: AsyncSession, username: str, password: str, role: str = "viewer") -> User:
    """Create a new user."""
    user = User(
        username=username,
        password_hash=hash_password(password),
        role=role,
    )
    session.add(user)
    await session.flush()
    logger.info("User created", extra={"extra_data": {"username": username, "role": role}})
    return user
