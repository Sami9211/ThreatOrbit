"""API versioning: a stable ``/v1`` surface over the existing routes.

Every API path is also served under ``/v1/...`` as an *exact alias* of the
unversioned path, so integrators can pin to a versioned contract while existing
clients (and the bundled frontend) keep working unversioned. See
``docs/API_VERSIONING.md`` for the deprecation policy.

Implemented as a pure-ASGI path rewrite rather than a second router include, so
there is **one** route table and no duplicate OpenAPI operations: a request to
``/v1/siem/alerts`` is rewritten to ``/siem/alerts`` before routing and tagged
with an ``X-API-Version: v1`` response header.
"""
API_VERSION = "v1"
_PREFIX = "/" + API_VERSION              # "/v1"
_PREFIX_SLASH = _PREFIX + "/"            # "/v1/"


class ApiVersionMiddleware:
    """Rewrite a leading ``/v1`` off the request path (so the existing handlers
    serve it) and stamp ``X-API-Version`` on the response. Added outermost so
    metrics/route-matching see the canonical path."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path != _PREFIX and not path.startswith(_PREFIX_SLASH):
            await self.app(scope, receive, send)
            return

        new_path = path[len(_PREFIX):] or "/"     # "/v1/x" → "/x"; "/v1" → "/"
        scope = dict(scope)
        scope["path"] = new_path
        raw = scope.get("raw_path")
        if raw:
            try:
                decoded = raw.decode("latin-1")
                if decoded.startswith(_PREFIX):
                    scope["raw_path"] = (decoded[len(_PREFIX):] or "/").encode("latin-1")
            except Exception:
                scope["raw_path"] = new_path.encode()

        async def send_with_version(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                headers.append((b"x-api-version", API_VERSION.encode()))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_version)


def mark_deprecated(response, *, sunset: str | None = None) -> None:
    """Flag a response as coming from a deprecated route (RFC 8594). Call this
    from a handler being retired and pair it with a CHANGELOG note + an OpenAPI
    ``deprecated=True`` on the route. ``sunset`` is an HTTP-date for the planned
    removal, e.g. ``"Wed, 01 Jan 2027 00:00:00 GMT"``."""
    response.headers["Deprecation"] = "true"
    if sunset:
        response.headers["Sunset"] = sunset


def stable_paths(app) -> list[str]:
    """Sorted path templates of the documented API - the surface the versioning
    contract promises not to remove (or breaking-change) without a version bump.
    Derived from the OpenAPI schema, so it tracks exactly what clients see
    (recursing into included routers, which app.routes wraps as mounts)."""
    return sorted(app.openapi().get("paths", {}).keys())
