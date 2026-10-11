#!/usr/bin/env python3
"""Engram Reader: synthetic local OAuth and opt-in Streamable HTTP adapter."""
import argparse
import asyncio
import base64
import hashlib
from collections import defaultdict, deque
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
import hmac
import html
import json
import logging
import os
import re
from pathlib import Path
import secrets
import time
import tempfile
from urllib.parse import urlparse
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import (AccessToken, AuthorizationCode, RefreshToken,
    AuthorizeError, TokenError, RegistrationError, construct_redirect_uri)
from mcp.server.auth.routes import build_metadata
from starlette.routing import request_response
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import FastMCP
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl, AnyUrl
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

import connector_store as c

CALLBACK = "http://localhost:8766/callback"
CLIENT_SCOPES = {"reader": "engram:read", "uploader": "engram:upload", "account": "engram:account"}


def token_key(token):
    """Opaque credentials have enough entropy for a one-way SHA-256 lookup key."""
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass(frozen=True)
class GrantFamily:
    client_id: str
    subject: str
    expires_at: int


class LocalAuthorization:
    """Local synthetic authority; only credential hashes persist in lookup maps."""
    MAX_PENDING = 100
    MAX_FAMILIES = 1000
    MAX_TOKEN_RECORDS = 10000

    def __init__(self, issuer, store, users, dcr=False):
        parsed = urlparse(issuer)
        if (parsed.hostname not in ("localhost", "localhost", "::1") or parsed.scheme not in ("http", "https")
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username):
            raise ValueError("local loopback issuer required")
        if not users or any(not isinstance(u, str) or not isinstance(p, str) or not p for u, p in users.items()):
            raise ValueError("synthetic credentials required")
        self.issuer = issuer.rstrip("/")
        self.resource = self.issuer + "/mcp"
        self.store, self.users, self.dcr = store, users, dcr
        self.clients = {name: OAuthClientInformationFull(client_id=name, redirect_uris=[AnyUrl(CALLBACK)],
                        scope=scope, token_endpoint_auth_method="none",
                        grant_types=["authorization_code", "refresh_token"], response_types=["code"])
                        for name, scope in CLIENT_SCOPES.items()}
        self.pending, self.codes, self.access, self.refresh = {}, {}, {}, {}
        self.families, self.family_tokens, self.client_expiry = {}, {}, {}
        self.grants, self.retired_refresh = {}, {}
        # Registration expiry prunes records but does not reset the local lifetime quota.
        self.registered_total = 0

    def active(self, subject):
        if subject not in self.users or self.store.policy != c.POLICY:
            return False
        try:
            self.store.active(c.Principal(subject, frozenset()))
            return True
        except c.Rejected:
            return False

    def forget_token(self, key):
        family = self.families.pop(key, None)
        self.access.pop(key, None)
        self.refresh.pop(key, None)
        self.retired_refresh.pop(key, None)
        members = self.family_tokens.get(family)
        if members is not None:
            members.discard(key)
            if not members:
                self.family_tokens.pop(family, None)
                self.grants.pop(family, None)

    def revoke_family(self, family):
        members = self.family_tokens.pop(family, set())
        for key in members:
            self.access.pop(key, None)
            self.refresh.pop(key, None)
            self.retired_refresh.pop(key, None)
            self.families.pop(key, None)
        self.grants.pop(family, None)

    def prune(self):
        now = time.time()
        for key, pending in list(self.pending.items()):
            if pending[2] <= now:
                self.pending.pop(key, None)
        for key, code in list(self.codes.items()):
            if code.expires_at <= now or not self.active(code.subject):
                self.codes.pop(key, None)
        for client_id, expires_at in list(self.client_expiry.items()):
            if expires_at <= now:
                self.client_expiry.pop(client_id, None)
                self.clients.pop(client_id, None)
        for family, grant in list(self.grants.items()):
            if grant.expires_at <= now or grant.client_id not in self.clients or not self.active(grant.subject):
                self.revoke_family(family)
        for key, access in list(self.access.items()):
            if access.expires_at <= now:
                self.forget_token(key)

    async def get_client(self, client_id):
        self.prune()
        return self.clients.get(client_id)

    async def register_client(self, client_info):
        self.prune()
        if (not self.dcr or self.registered_total >= 10 or client_info.scope != "engram:read"
                or [str(uri) for uri in client_info.redirect_uris or []] != [CALLBACK]
                or client_info.token_endpoint_auth_method != "none"):
            raise RegistrationError("invalid_client_metadata", "registration denied")
        self.clients[client_info.client_id] = client_info
        self.client_expiry[client_info.client_id] = time.time() + 3600
        self.registered_total += 1

    async def authorize(self, client, params):
        self.prune()
        if (params.resource != self.resource or params.scopes != client.scope.split()
                or str(params.redirect_uri) not in [str(uri) for uri in client.redirect_uris]
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.code_challenge)):
            raise AuthorizeError("access_denied", "authorization denied")
        if len(self.pending) >= self.MAX_PENDING:
            raise AuthorizeError("temporarily_unavailable", "try later")
        request_id = secrets.token_urlsafe(32)
        self.pending[request_id] = (client, params, time.time() + 300)
        return self.issuer + "/consent?request=" + request_id

    def consent(self, request_id, user, password, accepted):
        self.prune()
        pending = self.pending.pop(request_id, None)
        expected = self.users.get(user, secrets.token_urlsafe(32))
        verified = hmac.compare_digest(password.encode(), expected.encode())
        if pending is None or not verified or not self.active(user):
            raise c.Rejected("consent denied")
        client, params, _ = pending
        if not accepted:
            return construct_redirect_uri(str(params.redirect_uri), error="access_denied", state=params.state)
        if len(self.codes) >= self.MAX_PENDING:
            raise c.Rejected("consent unavailable")
        code = secrets.token_urlsafe(32)
        key = token_key(code)
        self.codes[key] = AuthorizationCode(code=key, scopes=params.scopes, expires_at=time.time() + 120,
            client_id=client.client_id, code_challenge=params.code_challenge, redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=self.resource, subject=user)
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    async def load_authorization_code(self, client, authorization_code):
        self.prune()
        code = self.codes.get(token_key(authorization_code))
        if code and code.client_id == client.client_id and self.active(code.subject):
            return code.model_copy(deep=True, update={"code": authorization_code})
        return None

    def issue(self, client_id, subject, scopes, family=None, deadline=None):
        self.prune()
        if ((family is None and len(self.grants) >= self.MAX_FAMILIES)
                or len(self.families) + 2 > self.MAX_TOKEN_RECORDS):
            if family is not None:
                self.revoke_family(family)
            raise TokenError("invalid_grant", "grant capacity reached")
        family = family or secrets.token_urlsafe(32)
        deadline = deadline or int(time.time()) + 30 * 86400
        expires_in = min(600, deadline - int(time.time()))
        if expires_in <= 0:
            raise TokenError("invalid_grant", "grant expired")
        self.grants[family] = GrantFamily(client_id, subject, deadline)
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        access_key, refresh_key = token_key(access), token_key(refresh)
        self.access[access_key] = AccessToken(token=access_key, client_id=client_id, scopes=scopes,
            expires_at=int(time.time()) + expires_in, resource=self.resource, subject=subject,
            claims={"iss": self.issuer})
        self.refresh[refresh_key] = RefreshToken(token=refresh_key, client_id=client_id, scopes=scopes,
            expires_at=deadline, resource=self.resource, subject=subject)
        members = self.family_tokens.setdefault(family, set())
        for key in (access_key, refresh_key):
            self.families[key] = family
            members.add(key)
        return OAuthToken(access_token=access, refresh_token=refresh, token_type="Bearer",
                          expires_in=expires_in, scope=" ".join(scopes))

    async def exchange_authorization_code(self, client, authorization_code):
        self.prune()
        code = self.codes.pop(token_key(authorization_code.code), None)
        if code is None or code.client_id != client.client_id or not self.active(code.subject):
            raise TokenError("invalid_grant", "grant unavailable")
        return self.issue(client.client_id, code.subject, code.scopes)

    async def load_refresh_token(self, client, refresh_token):
        self.prune()
        key = token_key(refresh_token)
        family = self.retired_refresh.get(key)
        grant = self.grants.get(family)
        if grant is not None and grant.client_id == client.client_id:
            self.revoke_family(family)
            return None
        token = self.refresh.get(key)
        if token and token.client_id == client.client_id and self.active(token.subject):
            return token.model_copy(deep=True, update={"token": refresh_token})
        return None

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        self.prune()
        key = token_key(refresh_token.token)
        old = self.refresh.get(key)
        if (old is None or old.client_id != client.client_id or not set(scopes) <= set(old.scopes)
                or not self.active(old.subject)):
            raise TokenError("invalid_grant", "grant unavailable")
        family = self.families[key]
        self.refresh.pop(key)
        self.retired_refresh[key] = family
        for member in list(self.family_tokens[family]):
            if member in self.access:
                self.forget_token(member)
        return self.issue(client.client_id, old.subject, scopes, family, old.expires_at)

    async def load_access_token(self, token):
        self.prune()
        access = self.access.get(token_key(token))
        if (access and access.resource == self.resource and access.claims.get("iss") == self.issuer
                and self.active(access.subject)):
            return access.model_copy(deep=True, update={"token": token})
        return None

    async def revoke_token(self, token):
        self.revoke_family(self.families.get(token_key(token.token)))

    def revoke_subject(self, subject):
        for family, grant in list(self.grants.items()):
            if grant.subject == subject:
                self.revoke_family(family)


class RateState:
    def __init__(self, max_keys=1000):
        self.max_keys = max_keys
        self.limits = defaultdict(deque)
        self.tool_calls = defaultdict(deque)
        self.active_tools = defaultdict(int)

    def prune(self, now=None):
        now = time.monotonic() if now is None else now
        for mapping in (self.limits, self.tool_calls):
            for key, queue in list(mapping.items()):
                while queue and queue[0] <= now - 60:
                    queue.popleft()
                if not queue and not self.active_tools.get(key, 0):
                    mapping.pop(key, None)
        for key, count in list(self.active_tools.items()):
            if count <= 0:
                self.active_tools.pop(key, None)



class BoundaryMiddleware(BaseHTTPMiddleware):
    """Local host, bounded input, content-free logs and shared IP limits."""
    def __init__(self, app, provider, rate_state=None):
        super().__init__(app)
        self.provider = provider
        self.rate_state = rate_state or RateState()
        self.limits = self.rate_state.limits
        self.tool_calls = self.rate_state.tool_calls
        self.active_tools = self.rate_state.active_tools

    def prune_rates(self, now=None):
        self.rate_state.prune(now)

    async def dispatch(self, request, call_next):
        started = time.monotonic()
        self.provider.prune()
        self.prune_rates(started)
        response = await self.handle(request, call_next)
        response.headers.update({
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
            "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer", "Cache-Control": "no-store", "Pragma": "no-cache",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cross-Origin-Opener-Policy": "same-origin",
        })
        if self.provider.issuer.startswith("https://"):
            response.headers["Strict-Transport-Security"] = "max-age=300"
        logging.getLogger("engram.operations").info(
            "request=%s status=%d duration_ms=%d request_bytes=%d response_bytes=%d",
            secrets.token_hex(12), response.status_code, (time.monotonic() - started) * 1000,
            len(getattr(request, "_body", b"")), int(response.headers.get("content-length", "0")))
        return response

    async def handle(self, request, call_next):
        started = time.monotonic()
        subject = None
        try:
            if request.url.hostname not in ("localhost", "localhost", "::1"):
                return JSONResponse({"error": "host denied"}, 400)
            origin = request.headers.get("origin")
            if origin and origin != self.provider.issuer:
                return JSONResponse({"error": "origin denied"}, 403)
            maximum = c.MAX_UPLOAD if request.url.path == "/upload" else 16 * 1024
            size = 0
            chunks = []
            async for chunk in request.stream():
                size += len(chunk)
                if size > maximum:
                    return JSONResponse({"error": "request too large"}, 413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
            if request.url.path in ("/authorize", "/consent", "/register", "/token"):
                key = request.client.host if request.client else "local"
                if key not in self.limits and len(self.limits) >= self.rate_state.max_keys:
                    return JSONResponse({"error": "rate capacity reached"}, 429, headers={"Retry-After": "60"})
                calls = self.limits[key]
                while calls and calls[0] < started - 60:
                    calls.popleft()
                if len(calls) >= 60:
                    return JSONResponse({"error": "rate exceeded"}, 429, headers={"Retry-After": "60"})
                calls.append(started)
            if request.url.path == "/token":
                form = await request.form()
                if form.get("grant_type") == "authorization_code" and not re.fullmatch(
                        r"[A-Za-z0-9._~-]{43,128}", str(form.get("code_verifier", ""))):
                    return JSONResponse({"error": "invalid_grant"}, 400)
                if form.get("grant_type") == "authorization_code":
                    client = await self.provider.get_client(str(form.get("client_id", "")))
                    code = (await self.provider.load_authorization_code(client, str(form.get("code", "")))
                            if client is not None else None)
                    if code is not None:
                        challenge = base64.urlsafe_b64encode(hashlib.sha256(
                            str(form["code_verifier"]).encode()).digest()).rstrip(b"=")
                        # Reject every mismatch before the SDK's ordinary equality check.
                        if not hmac.compare_digest(challenge, code.code_challenge.encode()):
                            return JSONResponse({"error": "invalid_grant"}, 400)
                if form.get("resource", self.provider.resource) != self.provider.resource:
                    return JSONResponse({"error": "invalid_target"}, 400)
            if request.url.path == "/mcp" and request.method == "POST":
                message = json.loads(request._body)
                if isinstance(message, dict) and message.get("method") == "tools/call":
                    bearer = request.headers.get("authorization", "")
                    token = await self.provider.load_access_token(bearer[7:]) if bearer.startswith("Bearer ") else None
                    if token and "engram:read" in token.scopes:
                        if token.subject not in self.tool_calls and len(self.tool_calls) >= self.rate_state.max_keys:
                            return JSONResponse({"error": "rate capacity reached"}, 429, headers={"Retry-After": "60"})
                        queue = self.tool_calls[token.subject]
                        while queue and queue[0] < started - 60:
                            queue.popleft()
                        if (len(queue) >= 60 or sum(t > started - 1 for t in queue) >= 10
                                or self.active_tools.get(token.subject, 0) >= 2):
                            return JSONResponse({"error": "tool rate exceeded"}, 429, headers={"Retry-After": "1"})
                        subject = token.subject
                        queue.append(started)
                        self.active_tools[subject] += 1
            response = await call_next(request)
            response.headers["Cache-Control"] = "no-store"
            return response
        except Exception:
            return JSONResponse({"error": "request failed"}, 400)
        finally:
            if subject is not None:
                self.active_tools[subject] -= 1
                if self.active_tools[subject] == 0:
                    self.active_tools.pop(subject, None)


class StrictFastMCP(FastMCP):
    async def call_tool(self, name, arguments):
        # FastMCP normally ignores extra fields and coerces argument types.
        # Check the original wire arguments before that conversion can occur.
        empty = {"version": "0.2.0", "exported_at": "", "sessions": [],
                 "observations": [], "prompts": []}
        try:
            c.read_tool(empty, name, arguments)
            return await super().call_tool(name, arguments)
        except Exception:
            raise c.Rejected("tool request denied") from None


def create_app(store, provider):
    server = StrictFastMCP("Engram Reader", host="localhost", json_response=True, stateless_http=True,
        log_level="CRITICAL", auth_server_provider=provider,
        auth=AuthSettings(issuer_url=AnyHttpUrl(provider.issuer),
            resource_server_url=AnyHttpUrl(provider.resource), validate_token_resource=True,
            required_scopes=["engram:read"], revocation_options=RevocationOptions(enabled=True),
            client_registration_options=ClientRegistrationOptions(enabled=provider.dcr,
                valid_scopes=list(CLIENT_SCOPES.values()), default_scopes=["engram:read"])))

    async def read(name, arguments):
        token = get_access_token()
        if token is None or await provider.load_access_token(token.token) is None:
            raise c.Rejected("access denied")
        principal = c.Principal(token.subject, frozenset(token.scopes))
        try:
            result = await asyncio.wait_for(asyncio.to_thread(store.call, principal, name, arguments), 10)
            if await provider.load_access_token(token.token) is None:
                raise c.Rejected("access denied")
            return result
        except Exception:
            raise c.Rejected("tool request denied") from None

    @server.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False})
    async def mem_search(query: str, project: str | None = None, limit: int = 20) -> dict[str, Any]:
        """Find matching observations in your filtered snapshot."""
        return await read("mem_search", {"query": query, "project": project, "limit": limit})

    @server.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False})
    async def mem_context(project: str | None = None, limit: int = 20) -> dict[str, Any]:
        """Read recent observations in your filtered snapshot."""
        return await read("mem_context", {"project": project, "limit": limit})

    @server.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False})
    async def mem_get_observation(id: int) -> dict[str, Any]:
        """Read one observation belonging to your snapshot."""
        return await read("mem_get_observation", {"id": id})

    @server.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False})
    async def mem_timeline(id: int, limit: int = 20) -> dict[str, Any]:
        """Read the observation's session history in your snapshot."""
        return await read("mem_timeline", {"id": id, "limit": limit})

    @server.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False})
    async def mem_stats() -> dict[str, Any]:
        """Read counts in your filtered snapshot."""
        return await read("mem_stats", {})

    @server.tool(annotations={"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False})
    async def mem_list_projects() -> dict[str, Any]:
        """List projects in your filtered snapshot."""
        return await read("mem_list_projects", {})

    @server.custom_route("/consent", methods=["GET", "POST"])
    async def consent(request):
        if request.method == "GET":
            request_id = request.query_params.get("request", "")
            pending = provider.pending.get(request_id)
            if pending is None or pending[2] <= time.time():
                provider.pending.pop(request_id, None)
                return JSONResponse({"error": "request unavailable"}, 400)
            scope = " ".join(provider.pending[request_id][1].scopes)
            return HTMLResponse('<h1>Engram Reader local test consent</h1><p>Scope: ' + html.escape(scope) +
                '</p><p>Read scope exposes six read tools and your filtered memory text to the connected client.</p>'
                '<form method="post"><input type="hidden" name="request" value="' + html.escape(request_id) +
                '"><label>Synthetic user <input name="user"></label>'
                '<label>Synthetic credential <input type="password" name="password"></label>'
                '<button name="consent" value="yes">Allow</button><button name="consent" value="no">Deny</button></form>')
        form = await request.form()
        try:
            target = provider.consent(str(form.get("request", "")), str(form.get("user", "")),
                                      str(form.get("password", "")), form.get("consent") == "yes")
            return RedirectResponse(target, status_code=302)
        except c.Rejected:
            return JSONResponse({"error": "consent denied"}, 403)

    async def principal(request, scope):
        bearer = request.headers.get("authorization", "")
        token = await provider.load_access_token(bearer[7:]) if bearer.startswith("Bearer ") else None
        if token is None:
            return None, JSONResponse({"error": "unauthorized"}, 401)
        p = c.Principal(token.subject, frozenset(token.scopes))
        try:
            c.require_scope(p, scope)
        except c.Rejected:
            return None, JSONResponse({"error": "scope denied"}, 403)
        return p, None

    @server.custom_route("/upload", methods=["POST"])
    async def upload(request):
        p, error = await principal(request, "engram:upload")
        if error is not None:
            return error
        try:
            result = await asyncio.to_thread(store.upload, p, await request.body())
            return JSONResponse(result)
        except c.RateLimited:
            return JSONResponse({"error": "upload rate exceeded"}, 429, headers={"Retry-After": "900"})
        except Exception:
            return JSONResponse({"error": "upload denied"}, 400)

    @server.custom_route("/account", methods=["DELETE"])
    async def delete(request):
        p, error = await principal(request, "engram:account")
        if error is not None:
            return error
        store.delete(p)
        provider.revoke_subject(p.subject)
        return JSONResponse({"deleted": True, "completed_at": int(time.time())})

    for tool in server._tool_manager.list_tools():
        tool.parameters["additionalProperties"] = False
    app = server.streamable_http_app()
    metadata = build_metadata(AnyHttpUrl(provider.issuer), None,
                              server.settings.auth.client_registration_options, RevocationOptions(enabled=True))
    metadata.token_endpoint_auth_methods_supported = ["none"]
    metadata.revocation_endpoint_auth_methods_supported = ["none"]

    async def discovery(request):
        return JSONResponse(metadata.model_dump(mode="json", exclude_none=True))

    async def revocation(request):
        form = await request.form()
        client = await provider.get_client(str(form.get("client_id", "")))
        token = str(form.get("token", ""))
        if client is None or not token:
            return JSONResponse({"error": "invalid_request"}, 400)
        found = (await provider.load_access_token(token)
                 or await provider.load_refresh_token(client, token))
        if found is not None and found.client_id == client.client_id:
            await provider.revoke_token(found)
        return JSONResponse({}, 200)

    for route in app.routes:
        if getattr(route, "path", None) == "/.well-known/oauth-authorization-server":
            route.app = request_response(discovery)
        if getattr(route, "path", None) == "/revoke":
            route.app = request_response(revocation)
    rate_state = RateState()
    app.add_middleware(BoundaryMiddleware, provider=provider, rate_state=rate_state)
    sdk_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application):
        async with sdk_lifespan(application):
            async def sweep():
                while True:
                    provider.prune()
                    rate_state.prune()
                    await asyncio.sleep(30)

            cleanup = asyncio.create_task(sweep())
            try:
                yield
            finally:
                cleanup.cancel()
                with suppress(asyncio.CancelledError):
                    await cleanup

    app.router.lifespan_context = lifespan
    # SDK/debug/access logs may include validation input. Only our fixed fields log.
    for name in ("mcp", "httpx", "httpcore", "uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers = [logging.NullHandler()]
        logger.propagate = False
        logger.disabled = True
    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--tls-cert", type=Path)
    parser.add_argument("--enable-dcr", action="store_true")
    args = parser.parse_args()
    try:
        # No secrets are accepted as command-line arguments or persisted in files.
        master = base64.urlsafe_b64decode(os.environ["ENGRAM_CONNECTOR_MASTER_KEY"])
        users = json.loads(os.environ["ENGRAM_CONNECTOR_SYNTHETIC_USERS"])
        tls_key = os.environ.get("ENGRAM_CONNECTOR_TLS_KEY")
        if bool(args.tls_cert) != bool(tls_key):
            raise ValueError("TLS certificate and environment key required")
        scheme = "https" if args.tls_cert else "http"
        store = c.TenantStore(args.state, master)
        provider = LocalAuthorization(f"{scheme}://localhost:{args.port}", store, users, args.enable_dcr)
        app = create_app(store, provider)
        import uvicorn
        with tempfile.TemporaryDirectory(prefix="engram-tls-") as scratch:
            key_path = Path(scratch) / "key.pem"
            if tls_key:
                key_path.touch(mode=0o600)
                key_path.write_text(tls_key)
            uvicorn.run(app, host="localhost", port=args.port, access_log=False, log_config=None,
                        ssl_certfile=str(args.tls_cert) if args.tls_cert else None,
                        ssl_keyfile=str(key_path) if tls_key else None)
    except Exception:
        print("Local connector failed; details withheld.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
