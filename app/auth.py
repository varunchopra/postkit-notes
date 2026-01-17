"""Authentication and authorization helpers."""

import logging
from datetime import timedelta

from flask import g, session
from psycopg.rows import dict_row

from .config import Config
from .db import get_authn, get_authz, get_db
from .security import REFRESH_TOKEN_PREFIX, create_token

log = logging.getLogger(__name__)


def create_session_with_refresh(
    user_id: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> dict:
    authn = get_authn()
    access_token, access_hash = create_token()
    refresh_token, refresh_hash = create_token(prefix=REFRESH_TOKEN_PREFIX)

    with get_db().transaction():
        session_id = authn.create_session(
            user_id=user_id,
            token_hash=access_hash,
            expires_in=timedelta(hours=Config.ACCESS_TOKEN_EXPIRES_HOURS),
            ip_address=ip_address,
            user_agent=user_agent[:1024] if user_agent else None,
        )

        authn.create_refresh_token(
            session_id=session_id,
            token_hash=refresh_hash,
            expires_in=timedelta(days=Config.REFRESH_TOKEN_EXPIRES_DAYS),
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": Config.ACCESS_TOKEN_EXPIRES_HOURS * 3600,
        "refresh_expires_in": Config.REFRESH_TOKEN_EXPIRES_DAYS * 86400,
    }


def logout_user() -> None:
    """Clear session state. Does NOT revoke DB session - caller must do that."""
    session.pop("token_hash", None)
    session.pop("current_org_id", None)


def get_session_user() -> str | None:
    token_hash = session.get("token_hash")
    if not token_hash:
        return None

    # Validate session against database
    db_session = get_authn().validate_session(token_hash)
    if not db_session:
        # Session revoked - clear Flask session
        session.clear()
        return None

    # Cache session_id for current session marking
    g.current_session_id = db_session.get("session_id")

    # Cache impersonation context for templates
    g.is_impersonating = db_session.get("is_impersonating", False)
    g.impersonator_id = db_session.get("impersonator_id")
    g.impersonator_email = db_session.get("impersonator_email")
    g.impersonation_reason = db_session.get("impersonation_reason")

    return db_session["user_id"]


def get_current_session_id() -> str | None:
    return g.get("current_session_id")


def get_or_create_sso_user(email: str) -> str:
    """Get or create user for SSO login. Raises AuthnError if user is disabled."""
    authn = get_authn()
    user_id, created = authn.get_or_create_user(email, password_hash=None)
    if created:
        log.info(f"SSO user created: user_id={user_id[:8]}...")
    return user_id


def get_user_orgs(user_id: str) -> list[dict]:
    with get_db().cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT o.org_id, o.name, o.slug, m.role, o.created_at
            FROM orgs o
            JOIN org_memberships m ON o.org_id = m.org_id
            WHERE m.user_id = %s
            ORDER BY o.name
            """,
            (user_id,),
        )
        return cur.fetchall()


def get_org_membership(user_id: str, org_id: str) -> dict | None:
    with get_db().cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT m.*, o.name as org_name, o.slug as org_slug
            FROM org_memberships m
            JOIN orgs o ON m.org_id = o.org_id
            WHERE m.user_id = %s AND m.org_id = %s
            """,
            (user_id, org_id),
        )
        return cur.fetchone()


def get_org(org_id: str) -> dict | None:
    with get_db().cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT * FROM orgs WHERE org_id = %s",
            (org_id,),
        )
        return cur.fetchone()


def get_org_by_slug(slug: str) -> dict | None:
    with get_db().cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT * FROM orgs WHERE slug = %s",
            (slug,),
        )
        return cur.fetchone()


API_KEY_LEVEL_PERMISSIONS = {
    "read": ["view"],
    "write": ["view", "edit"],
    "admin": ["view", "edit", "delete", "share"],
}


def grant_api_key_scopes(
    key_id: str,
    org_id: str,
    notes_access: str,
    notes_level: str = "read",
    selected_note_ids: list[str] | None = None,
) -> None:
    if notes_access == "none":
        return

    authz = get_authz(org_id)
    permissions = API_KEY_LEVEL_PERMISSIONS.get(notes_level, [])

    if notes_access == "all":
        for perm in permissions:
            authz.grant(perm, resource=("note", "*"), subject=("api_key", key_id))
    elif notes_access == "selected" and selected_note_ids:
        for note_id in selected_note_ids:
            for perm in permissions:
                authz.grant(
                    perm, resource=("note", note_id), subject=("api_key", key_id)
                )


def revoke_all_api_key_grants(key_id: str, org_id: str) -> int:
    authz = get_authz(org_id)
    return authz.revoke_all_grants(("api_key", key_id))


def get_api_key_scopes(key_id: str, org_id: str) -> dict:
    authz = get_authz(org_id)

    if authz.check(("api_key", key_id), "delete", ("note", "*")):
        return {"notes": "admin"}
    if authz.check(("api_key", key_id), "edit", ("note", "*")):
        return {"notes": "write"}
    if authz.check(("api_key", key_id), "view", ("note", "*")):
        return {"notes": "read"}

    grants = authz.list_grants(("api_key", key_id), resource_type="note")
    relations = {g["relation"] for g in grants}

    if "delete" in relations or "share" in relations:
        return {"notes": "selected:admin"}
    if "edit" in relations:
        return {"notes": "selected:write"}
    if "view" in relations:
        return {"notes": "selected:read"}

    return {"notes": "none"}


def get_api_key_scope_display(key_id: str, org_id: str) -> dict:
    scopes = get_api_key_scopes(key_id, org_id)

    display_map = {
        "admin": "Admin (full control)",
        "write": "Read and write",
        "read": "Read-only",
        "selected:admin": "Selected notes (admin)",
        "selected:write": "Selected notes (read/write)",
        "selected:read": "Selected notes (read-only)",
        "none": "No access",
    }

    return {"notes": display_map.get(scopes.get("notes", "none"), "No access")}
