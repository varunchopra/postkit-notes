"""Request context - single source of truth for authentication state."""

from dataclasses import dataclass
from typing import Optional

from flask import g


@dataclass(frozen=True)
class AuthMethod:
    type: str  # "session", "bearer", "api_key"
    credential_id: str  # session_id or api_key_id


@dataclass(frozen=True)
class ImpersonationContext:
    impersonator_id: str
    impersonator_email: str
    reason: str


@dataclass(frozen=True)
class RequestContext:
    """Immutable request context. Created once, never mutated."""

    user_id: str
    auth_method: AuthMethod
    org_id: Optional[str] = None
    impersonation: Optional[ImpersonationContext] = None
    request_id: str = ""
    ip_address: str = ""
    user_agent: str = ""

    @property
    def is_impersonating(self) -> bool:
        return self.impersonation is not None

    @property
    def session_id(self) -> Optional[str]:
        if self.auth_method.type in ("session", "bearer"):
            return self.auth_method.credential_id
        return None

    @property
    def api_key_id(self) -> Optional[str]:
        if self.auth_method.type == "api_key":
            return self.auth_method.credential_id
        return None

    @property
    def actor_id(self) -> str:
        if self.impersonation:
            return f"user:{self.impersonation.impersonator_id}"
        if self.api_key_id:
            return f"api_key:{self.api_key_id}"
        return f"user:{self.user_id}"

    @property
    def on_behalf_of(self) -> Optional[str]:
        if self.impersonation:
            return f"user:{self.user_id}"
        if self.api_key_id:
            return f"user:{self.user_id}"
        return None


# Type aliases for route signatures
UserContext = RequestContext  # user_id guaranteed
OrgContext = RequestContext  # user_id + org_id guaranteed


def set_context(ctx: RequestContext) -> None:
    if hasattr(g, "_security_context") and g._security_context is not None:
        raise RuntimeError("Security context already set for this request")
    g._security_context = ctx
