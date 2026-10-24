"""Real localhost Streamable HTTP, OAuth, uploads and six tools for two synthetic users."""
import asyncio
import base64
import hashlib
import json
import socket
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import time
from urllib.parse import parse_qs, urlparse
import httpx
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from test_connector import fixture
import connector_http as h
import connector_store as c


class EndToEndTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = c.TenantStore(Path(self.temp.name), b"s" * 32, upload_interval=0)
        sock = socket.socket()
        sock.bind(("localhost", 0))
        self.port = sock.getsockname()[1]
        self.base = f"http://localhost:{self.port}"
        self.provider = h.LocalAuthorization(self.base, self.store, {"alice": "synthetic-a", "bob": "synthetic-b"})
        self.server = uvicorn.Server(uvicorn.Config(h.create_app(self.store, self.provider),
                        host="localhost", port=self.port, access_log=False, log_config=None))
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [sock]}, daemon=True)
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                break
            await asyncio.sleep(.02)
        self.assertTrue(self.server.started)
        self.http = httpx.AsyncClient(base_url=self.base)

    async def asyncTearDown(self):
        await self.http.aclose()
        self.server.should_exit = True
        await asyncio.to_thread(self.thread.join, 5)
        self.assertFalse(self.thread.is_alive())

    async def token(self, user, client):
        verifier = "v" * 64
        response = await self.http.get("/authorize", params={"client_id": client, "response_type": "code",
            "redirect_uri": h.CALLBACK, "scope": h.CLIENT_SCOPES[client], "resource": self.base + "/mcp",
            "code_challenge_method": "S256", "code_challenge": base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")})
        request_id = parse_qs(urlparse(response.headers["location"]).query)["request"][0]
        consent = await self.http.post("/consent", data={"request": request_id, "user": user,
            "password": "synthetic-a" if user == "alice" else "synthetic-b", "consent": "yes"})
        code = parse_qs(urlparse(consent.headers["location"]).query)["code"][0]
        response = await self.http.post("/token", data={"client_id": client, "grant_type": "authorization_code",
            "code": code, "code_verifier": verifier, "redirect_uri": h.CALLBACK, "resource": self.base + "/mcp"})
        self.assertEqual(response.status_code, 200)
        return response.json()["access_token"]

    async def test_two_users_all_six_tools_and_schemas(self):
        for user in ("alice", "bob"):
            upload = await self.token(user, "uploader")
            response = await self.http.post("/upload", content=json.dumps(fixture(user)).encode(),
                         headers={"Authorization": "Bearer " + upload, "Content-Type": "application/json"})
            self.assertEqual(response.status_code, 200)
            token = await self.token(user, "reader")
            async with streamablehttp_client(self.base + "/mcp", headers={"Authorization": "Bearer " + token}) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    initialized = await session.initialize()
                    self.assertEqual(initialized.serverInfo.name, "Engram Reader")
                    listing = await session.list_tools()
                    self.assertEqual({t.name for t in listing.tools}, set(c.TOOL_NAMES))
                    for tool in listing.tools:
                        self.assertTrue(tool.annotations.readOnlyHint)
                        self.assertFalse(tool.annotations.destructiveHint)
                        self.assertFalse(tool.annotations.openWorldHint)
                        self.assertFalse(tool.inputSchema["additionalProperties"])
                    args = {"mem_search": {"query": user}, "mem_context": {},
                            "mem_get_observation": {"id": 1}, "mem_timeline": {"id": 1},
                            "mem_stats": {}, "mem_list_projects": {}}
                    for name, arguments in args.items():
                        result = await session.call_tool(name, arguments)
                        self.assertFalse(result.isError, name)
                        text = json.dumps(result.model_dump())
                        self.assertNotIn("bob" if user == "alice" else "alice", text)
                        self.assertLessEqual(len(text.encode()), c.MAX_RESPONSE)
                        if name in ("mem_get_observation", "mem_context", "mem_timeline", "mem_search"):
                            self.assertEqual(result.structuredContent["records"][0]["title"], user)
                    self.assertTrue((await session.call_tool("mem_stats", {"tenant": "bob"})).isError)
                    self.assertTrue((await session.call_tool("mem_save", {"content": "denied"})).isError)
                    self.assertTrue((await session.call_tool("unknown", {})).isError)

    async def test_upload_limit_and_revocation_over_real_http(self):
        upload = await self.token("alice", "uploader")
        result = await self.http.post("/upload", content=b"x" * (c.MAX_UPLOAD + 1),
                                      headers={"Authorization": "Bearer " + upload})
        self.assertEqual(result.status_code, 413)
        token = await self.token("bob", "reader")
        self.assertEqual((await self.http.post("/revoke", data={"client_id": "reader",
                            "token": token})).status_code, 200)
        self.assertEqual((await self.http.post("/mcp", json={},
                    headers={"Authorization": "Bearer " + token})).status_code, 401)

    async def test_wire_response_is_bounded_with_explicit_truncation(self):
        doc = fixture("alice")
        doc["data"]["observations"][0]["content"] = "x" * (40 * 1024)
        self.store.upload(c.Principal("alice", frozenset({"engram:upload"})), json.dumps(doc).encode())
        token = await self.token("alice", "reader")
        response = await self.http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "mem_context", "arguments": {}}}, headers={
                "Authorization": "Bearer " + token, "Accept": "application/json, text/event-stream"})
        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(response.content), c.MAX_RESPONSE)
        self.assertTrue(response.json()["result"]["structuredContent"]["truncated"])

    async def test_tool_burst_limit_returns_http_429(self):
        token = await self.token("alice", "reader")
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json, text/event-stream"}
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "mem_stats", "arguments": {}}}
        # Freeze only the boundary module's clock; the event loop and HTTP timeouts
        # keep real time. Slow hosted runners must still exercise one burst window.
        clock = SimpleNamespace(monotonic=lambda: 1000.0, time=time.time)
        with patch.object(h, "time", clock):
            statuses = [(await self.http.post("/mcp", json=payload, headers=headers)).status_code for _ in range(11)]
        self.assertEqual(statuses[:10], [200] * 10)
        self.assertEqual(statuses[-1], 429)


from policy_fixture import enable_policy

def setUpModule():
    global cleanup_policy
    cleanup_policy = enable_policy()

def tearDownModule():
    cleanup_policy()
