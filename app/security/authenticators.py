"""Authentication strategies (bearer, API key, session)."""

from dataclasses import dataclass
from typing import Optional

from flask import request, session

from .context import AuthMethod, ImpersonationContext
from .crypto import hash_token


@dataclass
class AuthResult:
    user_id: str
    auth_method: AuthMethod
    impersonation: Optional[ImpersonationContext] = None


def authenticate_request(authn_client) -> Optional[AuthResult]:
    """Try authentication methods in order: bearer token, API key, session cookie."""

    # Try bearer token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token_hash = hash_token(auth_header[7:])
        sess = authn_client.validate_session(token_hash)
        if sess:
            impersonation = None
            if sess.get("is_impersonating"):
                impersonation = ImpersonationContext(
                    impersonator_id=sess["impersonator_id"],
                    impersonator_email=sess["impersonator_email"],
                    reason=sess.get("impersonation_reason", ""),
                )
            return AuthResult(
                user_id=sess["user_id"],
                auth_method=AuthMethod("bearer", sess["session_id"]),
                impersonation=impersonation,
            )

    # Try API key
    api_key = request.headers.get("Api-Key")
    if api_key:
        key_info = authn_client.validate_api_key(hash_token(api_key))
        if key_info:
            return AuthResult(
                user_id=key_info["user_id"],
                auth_method=AuthMethod("api_key", key_info["key_id"]),
            )

    # Try session cookie
    token_hash = session.get("token_hash")
    if token_hash:
        db_session = authn_client.validate_session(token_hash)
        if db_session:
            impersonation = None
            if db_session.get("is_impersonating"):
                impersonation = ImpersonationContext(
                    impersonator_id=db_session["impersonator_id"],
                    impersonator_email=db_session["impersonator_email"],
                    reason=db_session.get("impersonation_reason", ""),
                )
            return AuthResult(
                user_id=db_session["user_id"],
                auth_method=AuthMethod("session", db_session["session_id"]),
                impersonation=impersonation,
            )
        else:
            # Invalid session - clear it
            session.clear()

    return None
