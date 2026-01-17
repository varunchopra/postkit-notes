"""Config schemas and seed data for the notes app."""

import logging

from postkit.config import ConfigClient

log = logging.getLogger(__name__)

SYSTEM_SCHEMAS = {
    "plans/": {
        "schema": {
            "type": "object",
            "required": ["name", "seats"],
            "properties": {
                "name": {"type": "string"},
                "seats": {"type": "integer"},
                "seat_price": {"type": ["number", "null"]},
                "storage_rate": {"type": ["number", "null"]},
            },
        },
        "description": "Plan definitions (free, pro, enterprise)",
    },
}

ORG_SCHEMAS = {
    "plan": {
        "schema": {"type": "string", "enum": ["free", "pro", "enterprise"]},
        "description": "Organization's current plan",
    },
    "settings": {
        "schema": {
            "type": "object",
            "properties": {
                "allow_public_notes": {"type": "boolean"},
                "default_share_permission": {"type": "string"},
            },
        },
        "description": "Organization settings",
    },
    "pricing": {
        "schema": {
            "type": "object",
            "properties": {
                "seat_price": {"type": "number"},
                "storage_rate": {"type": "number"},
            },
        },
        "description": "Enterprise pricing overrides",
    },
}

DEFAULT_PLANS = {
    "plans/free": {
        "name": "Free",
        "seats": 3,
        "seat_price": 0,
        "storage_rate": 0.00001,
    },
    "plans/pro": {
        "name": "Pro",
        "seats": 25,
        "seat_price": 10,
        "storage_rate": 0.000005,
    },
    "plans/enterprise": {
        "name": "Enterprise",
        "seats": -1,
        "seat_price": None,
        "storage_rate": None,
    },
}


def seed_schemas(config: ConfigClient) -> None:
    for pattern, defn in SYSTEM_SCHEMAS.items():
        config.set_schema(pattern, defn["schema"], defn["description"])
    for key, defn in ORG_SCHEMAS.items():
        config.set_schema(key, defn["schema"], defn["description"])
    log.info("Config schemas registered")


def seed_plans(config: ConfigClient) -> None:
    created_any = False
    for key, value in DEFAULT_PLANS.items():
        _, created = config.set_default(key, value)
        created_any = created_any or created
    if created_any:
        log.info("Default plans seeded")


def seed_all(config: ConfigClient) -> None:
    """Seed schemas and plans. Idempotent via seed_plans() check."""
    seed_schemas(config)
    seed_plans(config)
