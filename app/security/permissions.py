"""Permission checking utilities."""

from typing import Tuple

from .context import RequestContext


def check_permission(
    ctx: RequestContext,
    permission: str,
    resource: Tuple[str, str],
) -> bool:
    """For API keys: checks BOTH user permission AND key scope."""
    if not ctx.org_id:
        return False

    from ..db import get_authz

    authz = get_authz(ctx.org_id)

    if not authz.check(("user", ctx.user_id), permission, resource):
        return False

    if ctx.api_key_id:
        resource_type, resource_id = resource
        has_specific = authz.check(("api_key", ctx.api_key_id), permission, resource)
        has_wildcard = authz.check(
            ("api_key", ctx.api_key_id), permission, (resource_type, "*")
        )
        if not (has_specific or has_wildcard):
            return False

    return True


def is_org_member(user_id: str, org_id: str) -> bool:
    from ..db import get_db

    with get_db().cursor() as cur:
        cur.execute(
            "SELECT 1 FROM org_memberships WHERE user_id = %s AND org_id = %s",
            (user_id, org_id),
        )
        return cur.fetchone() is not None


def is_org_admin(user_id: str, org_id: str) -> bool:
    from ..db import get_authz

    return get_authz(org_id).check(("user", user_id), "admin", ("org", org_id))


def is_org_owner(user_id: str, org_id: str) -> bool:
    from ..db import get_authz

    return get_authz(org_id).check(("user", user_id), "owner", ("org", org_id))
