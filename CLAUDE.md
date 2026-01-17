# Claude Instructions

Don't write code that looks AI-generated.

Avoid: section banner comments (`# ====`), docstrings that restate the function name, "This module provides:" lists, comments on obvious code, over-engineered abstractions.

Comments should explain WHY, not WHAT. Good: `# Constant-time to prevent timing attacks`. Bad: `# Check if user exists`.

Skip docstrings when the signature is clear. Keep them when behavior is non-obvious.

Before documenting anything, verify it actually works. Don't document features that don't exist. Trace the code path.

## This Codebase

Multi-tenant: users are global, permissions are per-org (`org:{org_id}` namespace). API keys exist globally but their scopes live in one org's namespace.

Traps to avoid:
- Multi-step operations (like invite acceptance) need `with get_db().transaction():`
- Deleting entities must clean up authz grants in BOTH directions (entity as resource AND as subject)
- REST clients need `X-Org-Id` header since they don't have session cookies
- Use constants from `app/constants.py` for meter resource/unit strings

Frontend: no inline styles, no `<style>`/`<script>` blocks in templates, no template variables in `onclick` handlers. CSS colors must be variables. Every `:hover` needs `:focus-visible`.

## Before Committing

```
uvx ruff check app/ && uvx ruff format app/
```

Test the actual flow you changed. If you touched authz, verify cleanup on delete. If you touched templates, tab through the page.
