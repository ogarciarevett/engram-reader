# Privacy and architecture

Engram Reader exposes a filtered snapshot rather than the original Engram database. The local source is opened read-only. Export filters original fields before removing session summaries, directories and relation metadata. Rows with foreign session membership or deleted observations are excluded.

## Local private policy

The repository contains only `scripts/blocked-terms.example.json`, with an empty term list. Keep actual terms outside the checkout in `~/.config/engram-reader/blocked-terms.json`, an XDG config directory, or a file selected through `ENGRAM_READER_BLOCKLIST`. Use private filesystem permissions. No client-specific, company-specific or universally mandatory terms are distributed.

Matching normalizes case, Unicode compatibility characters, combining marks, invisible formatting characters and supported confusables. Empty terms are rejected. An empty list matches no text. All textual keys and values are checked before publishing or returning data. A pinned allowlist limits project scope; automatic mode selects eligible projects from the source.

On a failed refresh, the previous snapshot is retained only if it passes the current policy audit. A dirty or unverifiable snapshot is replaced with schema-only data, or removed if its schema cannot be read. Startup audits the snapshot before launching the six-tool MCP process. Each process receives a disposable copy with cloud autosync disabled and inherited Engram overrides removed.

## HTTP boundaries

OAuth subject and scopes determine tenant access. Request arguments cannot select a tenant, filesystem path or arbitrary SQL. Snapshots are encrypted with per-tenant keys derived from a master key, staged atomically, audited and published with private permissions. Reads run in a separate macOS sandbox process that denies network and filesystem writes and restricts storage reads. The configured private terms travel through stdin; the policy file is not opened by the sandbox.

Upload size, record counts, query length, page size and response bytes are bounded. Account deletion and policy changes cancel reads still in flight. Raw memory text, rejected input and credentials are withheld from error and access logs.

## Limits

Term filtering is a configurable exclusion mechanism, not a semantic guarantee that all sensitive information has been detected. Review the private blocklist and pinned project list before connecting a client. The empty example deliberately contains no deployment-specific policy. Client dialogs, OAuth callbacks and hosted registration must be verified separately with synthetic data.
