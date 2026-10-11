# Streamable HTTP and OAuth

The existing adapter exposes the same six read tools at `/mcp` using the MCP Python SDK's stateless Streamable HTTP transport. It supports a synthetic local OAuth authority, Authorization Code with PKCE S256, resource-bound access tokens, rotating refresh tokens, revocation and explicit consent. It is a development implementation for remote integrations, with no deployed public endpoint.

## Start a local development service

Use disposable synthetic accounts. Generate credentials in the environment rather than accepting them on the command line or committing them:

```sh
export ENGRAM_CONNECTOR_MASTER_KEY="$(.venv/bin/python -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())')"
export ENGRAM_CONNECTOR_SYNTHETIC_USERS="$(.venv/bin/python -c 'import json,secrets; print(json.dumps({"synthetic-user":secrets.token_urlsafe(32)}))')"
.venv/bin/python scripts/connector_http.py --state "$HOME/.local/share/engram-reader-http" --port 8765
```

Private blocklist lookup is the same as the local reader. The authority accepts loopback issuers only. A local TLS certificate can be passed with `--tls-cert`; the matching PEM key comes from `ENGRAM_CONNECTOR_TLS_KEY`.

The development clients are `reader` with `engram:read`, `uploader` with `engram:upload`, and `account` with `engram:account`. Their fixed callback is `http://localhost:8766/callback`. Optional `--enable-dcr` still restricts registrations to that callback, so it is insufficient for arbitrary clients' OAuth redirects. Tokens are resource-bound, and a read token cannot upload or delete an account.

## Export and upload

Prepare a pinned allowlist in a separate local policy state directory and an explicit private blocklist at the configured location. An empty blocklist must still be an explicit file for exports. The export command reads the source database with SQLite read-only access and produces strict data-only JSON:

```sh
.venv/bin/python scripts/filtered_export.py \
  --source "$HOME/.engram" \
  --policy-state "$HOME/.local/share/engram-reader" \
  --output "$HOME/.local/share/engram-reader/export.json"
```

Upload that file to `/upload` only after obtaining an uploader-scoped token through the consent flow. The server independently rechecks its configured blocklist and schema before encrypted publication. It also rechecks policy on reads. The sandbox receives the selected terms and one tenant snapshot through stdin without access to the private policy file or tenant storage. Remove the local export after use.

## Future HTTPS client configurations

The placeholder `https://connector.example/mcp` is not a deployed endpoint. These show the configuration shape after production OAuth registration and callbacks have been implemented and verified.

| Client | Configuration |
| --- | --- |
| Grok Bot | Setup → Plugins → Custom MCP server → Remote HTTPS; URL `https://connector.example/mcp`; exact dialog fields and OAuth callback remain to be confirmed |
| Cursor | `~/.cursor/mcp.json`: `{"mcpServers":{"engram-reader":{"url":"https://connector.example/mcp"}}}` |
| Claude Code | `.mcp.json`: `{"mcpServers":{"engram-reader":{"type":"http","url":"https://connector.example/mcp"}}}` |
| Codex | `~/.codex/config.toml`: `[mcp_servers.engram_reader]` with `url = "https://connector.example/mcp"`; then `codex mcp login engram_reader` |

The server design remains generic MCP. Grok Bot's app catalog does not establish a proprietary transport requirement. [Grok Bot custom server types](https://docs.x.ai/grok-bot/team-bots#plugins), [Cursor MCP](https://cursor.com/docs/mcp), [Claude Code MCP](https://code.claude.com/docs/en/mcp), [Codex MCP](https://developers.openai.com/codex/mcp).

## Deployment gates

Before using this with remote clients, implement a production HTTPS issuer and identity provider, register each client's actual redirect and registration contract, provision protected storage and stable encryption keys, and run end-to-end OAuth and tool-discovery acceptance in each client. The supplied authority has process-local synthetic accounts and token state; it is unsuitable as a hosted identity service. Worker isolation currently requires macOS. Publication of this source is separate from deploying or listing a hosted connector.
