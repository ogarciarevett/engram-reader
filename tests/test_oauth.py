"""Local OAuth protocol tests against the maintained MCP SDK endpoints."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from starlette.testclient import TestClient
from test_connector import fixture
import connector_http as h
import connector_store as c


class OAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = c.TenantStore(Path(self.temp.name), b"s" * 32, upload_interval=0)
        self.provider = h.LocalAuthorization("http://localhost:8765", self.store,
                                            {"alice": "synthetic-a", "bob": "synthetic-b"})
        self.client = self.enterContext(TestClient(h.create_app(self.store, self.provider),
                                                   base_url=self.provider.issuer))

    def authorize(self, user="alice", client="reader", consent="yes", verifier="v" * 64, exchange_verifier=None, exchange=True, **overrides):
        params = {"client_id": client, "response_type": "code",
                  "redirect_uri": h.CALLBACK, "scope": h.CLIENT_SCOPES[client],
                  "resource": self.provider.resource, "state": "synthetic-state",
                  "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("="),
                  "code_challenge_method": "S256"}
        params.update(overrides)
        response = self.client.get("/authorize", params=params, follow_redirects=False)
        if response.status_code != 302 or "request=" not in response.headers["location"]:
            return response
        request_id = response.headers["location"].split("request=")[1]
        response = self.client.post("/consent", data={"request": request_id, "user": user,
                    "password": "synthetic-a" if user == "alice" else "synthetic-b", "consent": consent},
                                    follow_redirects=False)
        if response.status_code != 302 or "code=" not in response.headers["location"]:
            return response
        from urllib.parse import parse_qs, urlparse
        code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
        self.last_code = code
        if not exchange:
            return code
        return self.client.post("/token", data={"grant_type": "authorization_code", "client_id": client,
                 "code": code, "redirect_uri": h.CALLBACK, "code_verifier": exchange_verifier or verifier,
                 "resource": self.provider.resource})

    def test_discovery_and_static_registration(self):
        meta = self.client.get("/.well-known/oauth-authorization-server").json()
        self.assertEqual(meta["code_challenge_methods_supported"], ["S256"])
        self.assertNotIn("registration_endpoint", meta)
        self.assertEqual(self.client.post("/register", json={}).status_code, 404)
        resource = self.client.get("/.well-known/oauth-protected-resource/mcp").json()
        self.assertEqual(resource["resource"], self.provider.resource)

    def test_consent_is_explicit_and_user_is_verified(self):
        self.assertNotEqual(self.authorize(consent="no").status_code, 200)
        token = self.authorize().json()
        self.assertIn("access_token", token)
        self.assertEqual(token["scope"], "engram:read")

    def test_wrong_scope_resource_and_redirect_are_rejected(self):
        for params in ({"scope": "engram:upload"}, {"resource": "https://other.invalid/mcp"},
                       {"redirect_uri": "http://localhost:9999/evil"}, {"code_challenge_method": "plain"}):
            with self.subTest(params=params):
                self.assertNotEqual(self.authorize(**params).status_code, 200)

    def test_refresh_rotates_and_revocation_stops_both_tokens(self):
        old = self.authorize().json()
        new = self.client.post("/token", data={"grant_type": "refresh_token", "client_id": "reader",
                "refresh_token": old["refresh_token"], "resource": self.provider.resource}).json()
        self.assertNotEqual(new["refresh_token"], old["refresh_token"])
        self.assertEqual(self.client.post("/token", data={"grant_type": "refresh_token", "client_id": "reader",
                "refresh_token": old["refresh_token"]}).status_code, 400)
        self.assertEqual(self.client.post("/revoke", data={"client_id": "reader",
                 "token": new["refresh_token"]}).status_code, 200)
        self.assertEqual(self.client.post("/mcp", headers={"Authorization": "Bearer " + new["access_token"]},
                                         json={}).status_code, 401)

    def test_upload_scope_is_separate_and_tenant_header_cannot_redirect_it(self):
        reader = self.authorize().json()["access_token"]
        self.assertEqual(self.client.post("/upload", content=json.dumps(fixture()).encode(),
                headers={"Authorization": "Bearer " + reader}).status_code, 403)
        upload = self.authorize(client="uploader").json()["access_token"]
        result = self.client.post("/upload", content=json.dumps(fixture()).encode(),
                headers={"Authorization": "Bearer " + upload, "X-Tenant": "bob"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.store.call(c.Principal("bob", frozenset({"engram:read"})), "mem_stats", {})["observations"], 0)
        self.assertEqual(self.client.post("/mcp", headers={"Authorization": "Bearer " + upload}, json={}).status_code, 403)

    def test_deleted_account_and_changed_policy_revoke_access(self):
        token = self.authorize().json()["access_token"]
        self.store.delete(c.Principal("alice", frozenset({"engram:account"})))
        self.assertEqual(self.client.post("/mcp", headers={"Authorization": "Bearer " + token}, json={}).status_code, 401)
        self.store.policy = "next"
        self.assertNotEqual(self.authorize(user="bob").status_code, 200)

    def test_expiry_is_checked_each_request(self):
        token = self.authorize().json()["access_token"]
        with patch.object(h.time, "time", return_value=h.time.time() + 601):
            self.assertEqual(self.client.post("/mcp", headers={"Authorization": "Bearer " + token}, json={}).status_code, 401)

    def test_logs_withhold_content_credentials_and_queries(self):
        with self.assertLogs("engram.operations", level="INFO") as logs:
            self.authorize()
            self.client.post("/token", data={"client_id": "reader", "grant_type": "bogus",
                                           "client_secret": "NEVER_LOG_THIS"})
        combined = "\n".join(logs.output)
        for sensitive in ("NEVER_LOG_THIS", "synthetic-a", "access_token", "alice", "code_challenge"):
            self.assertNotIn(sensitive, combined)

    def test_localhost_only_configuration(self):
        with self.assertRaises(ValueError):
            h.LocalAuthorization("https://public.example", self.store, {"alice": "secret"})

    def test_wrong_pkce_verifier_is_denied(self):
        self.assertEqual(self.authorize(exchange_verifier="wrong" * 12).status_code, 400)

    def test_dcr_flag_still_requires_exact_redirect_and_read_scope(self):
        self.provider.dcr = True
        with TestClient(h.create_app(self.store, self.provider), base_url=self.provider.issuer) as client:
            good = {"redirect_uris": [h.CALLBACK], "scope": "engram:read",
                    "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"]}
            result = client.post("/register", json=good)
            self.assertEqual(result.status_code, 201)
            for change in ({"scope": "engram:upload"}, {"redirect_uris": ["https://evil.invalid/callback"]}):
                self.assertNotEqual(client.post("/register", json={**good, **change}).status_code, 201)

    def test_forged_issuer_audience_and_subject_are_denied(self):
        for field, value in (("resource", "https://foreign.invalid/mcp"), ("subject", "foreign"),
                             ("claims", {"iss": "https://foreign.invalid"})):
            token = self.authorize().json()["access_token"]
            setattr(self.provider.access[h.token_key(token)], field, value)
            self.assertEqual(self.client.post("/mcp", headers={"Authorization": "Bearer " + token}, json={}).status_code, 401)

    def test_authorization_code_cannot_be_replayed(self):
        self.authorize()
        result = self.client.post("/token", data={"grant_type": "authorization_code", "client_id": "reader",
            "code": self.last_code, "redirect_uri": h.CALLBACK, "code_verifier": "v" * 64})
        self.assertEqual(result.status_code, 400)

    def test_discovery_advertises_public_static_clients(self):
        meta = self.client.get("/.well-known/oauth-authorization-server").json()
        self.assertIn("none", meta["token_endpoint_auth_methods_supported"])

    def test_tls_key_comes_from_environment_and_temporary_file_is_removed(self):
        import os
        import sys
        visited = []

        def capture(app, **options):
            path = Path(options["ssl_keyfile"])
            self.assertEqual(path.read_text(), "synthetic TLS key")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(options["host"], "localhost")
            self.assertFalse(options["access_log"])
            visited.append(path)

        with patch.dict(os.environ, {"ENGRAM_CONNECTOR_MASTER_KEY": base64.urlsafe_b64encode(b"s" * 32).decode(),
                "ENGRAM_CONNECTOR_SYNTHETIC_USERS": '{"alice":"synthetic-a","bob":"synthetic-b"}',
                "ENGRAM_CONNECTOR_TLS_KEY": "synthetic TLS key"}), patch.object(sys, "argv", [
                "connector_http.py", "--state", str(Path(self.temp.name) / "tls-state"),
                "--tls-cert", "synthetic-public-cert.pem"]), patch("uvicorn.run", side_effect=capture):
            self.assertEqual(h.main(), 0)
        self.assertEqual(len(visited), 1)
        self.assertFalse(visited[0].exists())

    def test_pkce_verifier_must_meet_rfc7636_length(self):
        self.assertEqual(self.authorize(verifier="tiny").status_code, 400)

    def test_public_client_revokes_refresh_without_client_secret(self):
        issued = self.authorize().json()
        response = self.client.post("/revoke", data={"client_id": "reader",
                                    "token": issued["refresh_token"]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.post("/mcp", headers={
            "Authorization": "Bearer " + issued["access_token"]}, json={}).status_code, 401)

    def test_security_headers_cover_consent_and_errors(self):
        for response in (self.client.get("/consent?request=missing"),
                         self.client.get("/.well-known/oauth-authorization-server"),
                         self.client.post("/consent", headers={"Origin": "https://foreign.invalid"})):
            self.assertIn("frame-ancestors 'none'", response.headers.get("Content-Security-Policy", ""))
            self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
            self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertEqual(response.headers.get("Referrer-Policy"), "no-referrer")
            self.assertEqual(response.headers.get("Cache-Control"), "no-store")

    def test_expired_consent_page_is_rejected_and_pruned(self):
        verifier = "v" * 64
        response = self.client.get("/authorize", params={"client_id": "reader", "response_type": "code",
            "redirect_uri": h.CALLBACK, "scope": "engram:read", "resource": self.provider.resource,
            "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("="),
            "code_challenge_method": "S256"}, follow_redirects=False)
        location = response.headers["location"]
        with patch.object(h.time, "time", return_value=h.time.time() + 301):
            result = self.client.get(location)
        self.assertEqual(result.status_code, 400)
        self.assertEqual(self.provider.pending, {})

    def test_pkce_mismatch_uses_constant_time_precheck(self):
        with patch.object(h.hmac, "compare_digest", wraps=h.hmac.compare_digest) as compare:
            self.assertEqual(self.authorize(exchange_verifier="wrong" * 12).status_code, 400)
        self.assertTrue(any(len(call.args[0]) == len(call.args[1]) == 43 for call in compare.call_args_list))

    def test_token_lookup_maps_store_hashes_instead_of_bearer_text(self):
        issued = self.authorize().json()
        for name in ("access_token", "refresh_token"):
            raw = issued[name]
            digest = hashlib.sha256(raw.encode()).hexdigest()
            mapping = self.provider.access if name == "access_token" else self.provider.refresh
            self.assertTrue(raw not in mapping, "bearer lookup keys must be hashed")
            self.assertIn(digest, mapping)
            self.assertEqual(mapping[digest].token, digest)
            self.assertNotIn(raw, self.provider.families)
            self.assertTrue(all(raw not in members for members in self.provider.family_tokens.values()))

    def test_refresh_reuse_revokes_the_entire_family_only_for_the_bound_client(self):
        old = self.authorize().json()
        rotated = self.client.post("/token", data={"client_id": "reader", "grant_type": "refresh_token",
                                  "refresh_token": old["refresh_token"]}).json()
        # A different public client cannot use an old token to revoke this grant.
        self.assertEqual(self.client.post("/token", data={"client_id": "uploader", "grant_type": "refresh_token",
                           "refresh_token": old["refresh_token"]}).status_code, 400)
        self.assertNotEqual(self.client.post("/mcp", json={}, headers={
            "Authorization": "Bearer " + rotated["access_token"]}).status_code, 401)
        self.assertEqual(self.client.post("/token", data={"client_id": "reader", "grant_type": "refresh_token",
                           "refresh_token": old["refresh_token"]}).status_code, 400)
        self.assertEqual(self.client.post("/mcp", json={}, headers={
            "Authorization": "Bearer " + rotated["access_token"]}).status_code, 401)
        self.assertEqual(self.client.post("/token", data={"client_id": "reader", "grant_type": "refresh_token",
                           "refresh_token": rotated["refresh_token"]}).status_code, 400)

    def test_expired_codes_tokens_and_families_are_pruned(self):
        self.authorize(exchange=False)
        issued = self.authorize().json()
        with patch.object(h.time, "time", return_value=h.time.time() + 31 * 86400):
            self.client.get("/.well-known/oauth-authorization-server")
        for name in ("pending", "codes", "access", "refresh", "families", "family_tokens"):
            self.assertEqual(getattr(self.provider, name), {}, name)

    def test_expired_access_pruning_preserves_the_refresh_grant(self):
        issued = self.authorize().json()
        with patch.object(h.time, "time", return_value=h.time.time() + 601):
            self.client.get("/.well-known/oauth-authorization-server")
            self.assertEqual(self.provider.access, {})
            self.assertEqual(len(self.provider.refresh), 1)
            response = self.client.post("/token", data={"client_id": "reader", "grant_type": "refresh_token",
                                   "refresh_token": issued["refresh_token"]})
            self.assertEqual(response.status_code, 200)

    def test_rate_limit_maps_prune_idle_keys(self):
        self.client.get("/authorize")
        middleware = self.client.app.middleware_stack
        while not isinstance(middleware, h.BoundaryMiddleware):
            middleware = middleware.app
        with patch.object(h.time, "monotonic", return_value=h.time.monotonic() + 61):
            self.client.get("/.well-known/oauth-authorization-server")
        self.assertEqual(middleware.limits, {})
        self.assertEqual(middleware.tool_calls, {})
        self.assertEqual(middleware.active_tools, {})

    def test_dcr_expiry_prunes_records_but_preserves_the_ten_registration_lifetime_cap(self):
        self.provider.dcr = True
        with TestClient(h.create_app(self.store, self.provider), base_url=self.provider.issuer) as client:
            registration = {"redirect_uris": [h.CALLBACK], "scope": "engram:read",
                            "token_endpoint_auth_method": "none"}
            for _ in range(10):
                self.assertEqual(client.post("/register", json=registration).status_code, 201)
            with patch.object(h.time, "time", return_value=h.time.time() + 3601):
                client.get("/.well-known/oauth-authorization-server")
                self.assertEqual(self.provider.client_expiry, {})
                self.assertEqual(set(self.provider.clients), set(h.CLIENT_SCOPES))
                self.assertEqual(client.post("/register", json=registration).status_code, 400)
            self.assertEqual(self.provider.registered_total, 10)

    def test_grant_capacity_fails_closed_and_pruning_reclaims_capacity(self):
        self.provider.MAX_FAMILIES = 1
        self.authorize()
        self.assertEqual(self.authorize(user="bob").status_code, 400)
        with patch.object(h.time, "time", return_value=h.time.time() + 31 * 86400):
            self.assertEqual(self.authorize(user="bob").status_code, 200)
        self.assertEqual(len(self.provider.grants), 1)

    def test_reuse_tombstones_are_removed_with_the_expired_family(self):
        old = self.authorize().json()
        self.client.post("/token", data={"client_id": "reader", "grant_type": "refresh_token",
                                       "refresh_token": old["refresh_token"]})
        self.assertEqual(len(self.provider.retired_refresh), 1)
        with patch.object(h.time, "time", return_value=h.time.time() + 31 * 86400):
            self.client.get("/.well-known/oauth-authorization-server")
        for name in ("grants", "retired_refresh", "families", "family_tokens"):
            self.assertEqual(getattr(self.provider, name), {}, name)

    def test_unused_authorization_codes_are_stored_under_hashes(self):
        code = self.authorize(exchange=False)
        self.assertTrue(code not in self.provider.codes, "code lookup must not retain its bearer value")
        self.assertEqual(self.provider.codes[h.token_key(code)].code, h.token_key(code))


from policy_fixture import enable_policy

def setUpModule():
    global cleanup_policy
    cleanup_policy = enable_policy()

def tearDownModule():
    cleanup_policy()
