"""API routes - all prefixed with /api."""

from flask import Blueprint, jsonify

from . import admin, api_keys, health, notes, orgs, sso, users

api_bp = Blueprint("api", __name__, url_prefix="/api")
api_bp.register_blueprint(health.bp)
api_bp.register_blueprint(users.bp)
api_bp.register_blueprint(sso.bp)
api_bp.register_blueprint(api_keys.bp)
api_bp.register_blueprint(notes.bp)
api_bp.register_blueprint(orgs.bp)
api_bp.register_blueprint(admin.bp)


def api_error(code: str, message: str, status: int):
    """Consistent API error response format."""
    return jsonify({"error": {"code": code, "message": message}}), status


__all__ = ["api_bp", "api_error"]
