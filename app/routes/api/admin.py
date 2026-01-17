"""Admin API endpoints for system maintenance."""

import logging

from flask import Blueprint, jsonify

from ...db import get_authn, get_authz, get_meter
from ...security import OrgContext, authenticated

bp = Blueprint("api_admin", __name__, url_prefix="/admin")
log = logging.getLogger(__name__)


@bp.post("/cleanup")
@authenticated(org=True, admin=True)
def run_cleanup(ctx: OrgContext):
    """Run cleanup tasks for expired grants, sessions, and reservations.

    Requires org admin permission. Cleans up:
    - Expired authz grants in this org
    - Expired sessions (global)
    - Expired meter reservations in this org
    """
    results = {}

    # Clean up expired authz grants for this org
    try:
        authz = get_authz(ctx.org_id)
        expired_grants = authz.cleanup_expired()
        results["expired_grants"] = expired_grants
    except Exception as e:
        log.warning(f"Authz cleanup failed: {e}")
        results["expired_grants"] = {"error": str(e)}

    # Clean up expired sessions (global authn)
    try:
        authn = get_authn()
        expired_sessions = authn.cleanup_expired()
        results["expired_sessions"] = expired_sessions
    except Exception as e:
        log.warning(f"Authn cleanup failed: {e}")
        results["expired_sessions"] = {"error": str(e)}

    # Clean up expired meter reservations for this org
    try:
        meter = get_meter(ctx.org_id)
        expired_reservations = meter.release_expired_reservations()
        results["expired_reservations"] = expired_reservations
    except Exception as e:
        log.warning(f"Meter cleanup failed: {e}")
        results["expired_reservations"] = {"error": str(e)}

    log.info(f"Cleanup completed for org_id={ctx.org_id[:8]}...: {results}")
    return jsonify({"ok": True, "results": results})
