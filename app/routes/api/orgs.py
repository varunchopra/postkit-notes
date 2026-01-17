"""Organizations API - list orgs for authenticated user."""

from flask import Blueprint, jsonify

from ...auth import get_user_orgs
from ...security import UserContext, authenticated

bp = Blueprint("api_orgs", __name__, url_prefix="/orgs")


@bp.get("")
@authenticated
def list_orgs(ctx: UserContext):
    """List organizations the authenticated user belongs to."""
    orgs = get_user_orgs(ctx.user_id)
    return jsonify(
        {
            "orgs": [
                {
                    "id": o["org_id"],
                    "name": o["name"],
                    "slug": o["slug"],
                    "role": o["role"],
                }
                for o in orgs
            ]
        }
    )
