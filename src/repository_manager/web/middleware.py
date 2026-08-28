"""ASGI middleware: proxy trust, request identity, and security headers.

Ordering matters.  Proxy resolution runs first because everything downstream --
the scheme used for cookie flags, the client IP recorded in the audit log, and
the prefix used to build URLs -- depends on its output.
"""

from __future__ import annotations

import secrets
import time
from typing import Any

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from repository_manager.config import Settings
from repository_manager.logging import get_logger, request_id_var

log = get_logger(__name__)

# Features the application never uses.  Denying them shrinks the attack surface
# available to any content that does manage to execute.
PERMISSIONS_POLICY = ", ".join(
    f"{feature}=()"
    for feature in (
        "accelerometer",
        "autoplay",
        "camera",
        "display-capture",
        "encrypted-media",
        "fullscreen",
        "geolocation",
        "gyroscope",
        "magnetometer",
        "microphone",
        "midi",
        "payment",
        "usb",
        "xr-spatial-tracking",
    )
)

HSTS_VALUE = "max-age=31536000; includeSubDomains"


def _split_forwarded(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


class ProxyHeadersMiddleware:
    """Honour ``X-Forwarded-*`` only from configured proxies (specification.md 10.6).

    With ``REPOMAN_TRUSTED_PROXIES`` unset every forwarded header is ignored and
    the peer address is used directly, so an unauthenticated client cannot spoof
    its source IP to escape a rate limit or poison the audit trail.

    The middleware also normalises the mount prefix: whether the proxy strips
    the prefix and announces it via ``X-Forwarded-Prefix`` or passes the whole
    path through untouched, the application downstream always sees
    ``root_path`` set to the prefix and ``path`` still containing it -- which is
    the shape Starlette's own routing expects.  :func:`route_path` is the way
    back to the path without it.
    """

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        peer = scope.get("client")
        peer_host = peer[0] if peer else None
        trusted = self.settings.is_trusted_proxy(peer_host)

        client_ip = peer_host
        prefix = self.settings.effective_root_path

        if trusted:
            forwarded_for = headers.get("x-forwarded-for")
            if forwarded_for:
                client_ip = self._client_from_forwarded_for(forwarded_for) or peer_host

            proto = headers.get("x-forwarded-proto")
            if proto:
                # A proxy chain may append; the original client's scheme is first.
                scope["scheme"] = _split_forwarded(proto)[0]

            host = headers.get("x-forwarded-host")
            if host:
                mutable = MutableHeaders(scope=scope)
                mutable["host"] = _split_forwarded(host)[0]

            forwarded_prefix = headers.get("x-forwarded-prefix")
            if forwarded_prefix:
                prefix = "/" + forwarded_prefix.strip().strip("/")
                if prefix == "/":
                    prefix = ""

        scope["client_ip"] = client_ip
        self._apply_prefix(scope, prefix)
        await self.app(scope, receive, send)

    def _client_from_forwarded_for(self, value: str) -> str | None:
        """Right-most entry that is not itself a trusted proxy (10.6).

        Walking from the right skips the hops we control; anything further left
        was supplied by an untrusted party and cannot be believed.
        """
        for candidate in reversed(_split_forwarded(value)):
            if not self.settings.is_trusted_proxy(candidate):
                return candidate
        return None

    @staticmethod
    def _apply_prefix(scope: Scope, prefix: str) -> None:
        """Guarantee ``root_path == prefix`` and that ``path`` still contains it.

        Both proxy styles have to work: one passes the prefix through in the
        path, the other strips it and announces it via ``X-Forwarded-Prefix``.
        This normalises the second case into the first.

        Note the direction.  Starlette's ``get_route_path`` derives the routable
        path by removing ``root_path`` from ``path``, and ``Mount`` extends
        ``root_path`` with its own prefix for the sub-application.  Stripping the
        prefix here instead would satisfy top-level routes but leave every
        mounted app (the static files) computing a route path that no longer
        matches -- a 404 for the stylesheet and nothing else.
        """
        scope["root_path"] = prefix
        if not prefix:
            return
        path = scope.get("path", "")
        if path == prefix or path.startswith(prefix + "/"):
            return
        scope["path"] = f"{prefix}{path}"


class RequestContextMiddleware:
    """Assign a request ID, bind it to the log context, and time the request."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = secrets.token_hex(8)
        scope["request_id"] = request_id
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        status_code = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = MutableHeaders(scope=message)
                headers["x-request-id"] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            # Health probes would otherwise dominate the log at one line per
            # second; they are still counted by metrics.
            # Compared against the routed path, so a sub-path deployment does
            # not start logging one line a second per probe (13.5).
            if route_path(scope) not in {"/healthz", "/readyz"}:
                log.info(
                    "request",
                    method=scope.get("method"),
                    # `path` already carries the prefix -- ProxyHeadersMiddleware
                    # puts it back when the proxy stripped it -- so this is the
                    # externally visible path, not a fragment of one.
                    path=scope.get("path", ""),
                    status=status_code,
                    duration_ms=duration_ms,
                    client_ip=scope.get("client_ip"),
                )
            request_id_var.reset(token)


class SecurityHeadersMiddleware:
    """Apply the response headers required by specification.md 10.1.

    The CSP nonce is generated per request and exposed on the scope so templates
    can mark the one stylesheet link that needs it.  There is no ``unsafe-inline``
    anywhere: HTMX is vendored and served from this origin (AD-9).
    """

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings

    def _csp(self, nonce: str) -> str:
        return "; ".join(
            (
                "default-src 'self'",
                f"script-src 'self' 'nonce-{nonce}'",
                f"style-src 'self' 'nonce-{nonce}'",
                "img-src 'self' data:",
                "font-src 'self'",
                "connect-src 'self'",
                "form-action 'self'",
                "frame-ancestors 'none'",
                "base-uri 'none'",
                "object-src 'none'",
            )
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        nonce = secrets.token_urlsafe(16)
        scope["csp_nonce"] = nonce

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("content-security-policy", self._csp(nonce))
                headers.setdefault("x-content-type-options", "nosniff")
                headers.setdefault("referrer-policy", "strict-origin-when-cross-origin")
                headers.setdefault("x-frame-options", "DENY")
                headers.setdefault("cross-origin-opener-policy", "same-origin")
                headers.setdefault("permissions-policy", PERMISSIONS_POLICY)
                # HSTS only over https, and only when the proxy is not already
                # sending it -- a duplicated header is a configuration smell.
                if self.settings.send_hsts and scope.get("scheme") == "https":
                    headers.setdefault("strict-transport-security", HSTS_VALUE)
            await send(message)

        await self.app(scope, receive, send_wrapper)


def route_path(scope: Scope) -> str:
    """The request path with the mount prefix removed (13.5).

    :meth:`ProxyHeadersMiddleware._apply_prefix` guarantees that ``path``
    contains the prefix and that ``root_path`` *is* the prefix, so this is the
    path the router matched against -- the same value Starlette computes
    internally to dispatch the request.  Written out here rather than imported
    from Starlette because that helper is not part of its public surface, and a
    security decision (:func:`repository_manager.web.deps.is_api_request`) is
    made on the answer.
    """
    path = str(scope.get("path", ""))
    prefix = str(scope.get("root_path", ""))
    if prefix and path.startswith(prefix):
        return path[len(prefix) :] or "/"
    return path


def client_ip(scope: Scope | Any) -> str | None:
    """The resolved client IP, for audit and rate-limiting call sites."""
    if isinstance(scope, dict):
        return scope.get("client_ip")
    return getattr(scope, "client_ip", None)
