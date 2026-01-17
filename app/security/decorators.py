"""Authentication decorator with automatic validation."""

import uuid
from functools import wraps
from typing import Callable, Optional, TypeVar, Union

from flask import g, jsonify, redirect, request, session, url_for
from werkzeug.exceptions import BadRequest

from .authenticators import authenticate_request
from .context import RequestContext, set_context
from .permissions import is_org_admin, is_org_member
from .validators import validate_url_params

F = TypeVar("F", bound=Callable)


def _is_api_request() -> bool:
    return (
        request.accept_mimetypes.best == "application/json"
        or request.is_json
        or request.path.startswith("/api/")
    )


def _error_response(code: int, message: str, redirect_url: Optional[str] = None):
    if _is_api_request():
        return jsonify({"error": message}), code
    if redirect_url:
        return redirect(redirect_url)
    return message, code


def _resolve_org_id(kwargs: dict) -> Optional[str]:
    """Priority: URL param > Header > Session"""
    sources = [
        kwargs.get("org_id"),
        request.headers.get("X-Org-Id"),
        session.get("current_org_id"),
    ]
    unique = {s for s in sources if s}

    if len(unique) > 1:
        raise BadRequest("Conflicting org_id values in request")

    return next(iter(unique), None)


def _set_audit_actor(ctx: RequestContext) -> None:
    from ..db import get_authn, get_authz

    reason = None
    if ctx.impersonation:
        reason = ctx.impersonation.reason

    authn = get_authn()
    authn.set_actor(
        actor_id=ctx.actor_id,
        on_behalf_of=ctx.on_behalf_of,
        reason=reason,
    )

    if ctx.org_id:
        authz = get_authz(ctx.org_id)
        authz.set_actor(
            actor_id=ctx.actor_id,
            on_behalf_of=ctx.on_behalf_of,
            reason=reason,
        )


def authenticated(
    f: Optional[F] = None,
    *,
    org: bool = False,
    admin: bool = False,
    validate_params: bool = True,
) -> Union[F, Callable[[F], F]]:
    require_org = org or admin

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args, **kwargs):
            from ..db import get_authn

            auth_result = authenticate_request(get_authn())
            if not auth_result:
                return _error_response(
                    401,
                    "unauthorized",
                    url_for("views.auth.login") if not _is_api_request() else None,
                )

            org_id = None
            if require_org:
                try:
                    org_id = _resolve_org_id(kwargs)
                except BadRequest as e:
                    return _error_response(400, str(e))

                if not org_id:
                    return _error_response(
                        400,
                        "org_id required",
                        url_for("views.orgs.select") if not _is_api_request() else None,
                    )

                if not is_org_member(auth_result.user_id, org_id):
                    session.pop("current_org_id", None)
                    return _error_response(403, "not a member of this organization")

                if admin and not is_org_admin(auth_result.user_id, org_id):
                    return _error_response(403, "admin required")

            if require_org and validate_params and org_id:
                try:
                    params_to_validate = {
                        k: v for k, v in kwargs.items() if k != "org_id"
                    }
                    validate_url_params(org_id, params_to_validate)
                except Exception:
                    return _error_response(404, "not found")

            ctx = RequestContext(
                user_id=auth_result.user_id,
                auth_method=auth_result.auth_method,
                org_id=org_id,
                impersonation=auth_result.impersonation,
                request_id=g.get("request_id", str(uuid.uuid4())),
                ip_address=request.remote_addr or "",
                user_agent=request.headers.get("User-Agent", "")[:1024],
            )
            set_context(ctx)
            _set_audit_actor(ctx)

            g.is_impersonating = ctx.is_impersonating
            if ctx.impersonation:
                g.impersonator_id = ctx.impersonation.impersonator_id
                g.impersonator_email = ctx.impersonation.impersonator_email
                g.impersonation_reason = ctx.impersonation.reason

            if org_id:
                g.org_id = org_id

            return func(ctx, *args, **kwargs)

        return wrapper

    if f is not None:
        return decorator(f)
    return decorator
