"""URL parameter validators - auto-validates that params belong to current org."""

from typing import Callable, Dict

from werkzeug.exceptions import NotFound

from .permissions import is_org_member

_validators: Dict[str, Callable[[str, str], bool]] = {}


def register_validator(param_name: str, validator: Callable[[str, str], bool]) -> None:
    _validators[param_name] = validator


def validate_url_params(org_id: str, kwargs: dict) -> None:
    for param_name, param_value in kwargs.items():
        if param_name in _validators and param_value:
            if not _validators[param_name](param_value, org_id):
                raise NotFound(f"{param_name} not found")


def _is_team_in_org(team_id: str, org_id: str) -> bool:
    from ..db import get_db

    with get_db().cursor() as cur:
        cur.execute(
            "SELECT 1 FROM teams WHERE team_id = %s AND org_id = %s",
            (team_id, org_id),
        )
        return cur.fetchone() is not None


def _is_note_in_org(note_id: str, org_id: str) -> bool:
    from ..db import get_db

    with get_db().cursor() as cur:
        cur.execute(
            "SELECT 1 FROM notes WHERE note_id = %s AND org_id = %s",
            (note_id, org_id),
        )
        return cur.fetchone() is not None


# Register built-in validators
register_validator("user_id", is_org_member)
register_validator("member_id", is_org_member)
register_validator("team_id", _is_team_in_org)
register_validator("note_id", _is_note_in_org)
