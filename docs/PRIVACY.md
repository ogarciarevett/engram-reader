# Privacy and architecture

Engram Reader exposes a filtered snapshot rather than the original Engram database. The local source is opened read-only. Export filters original fields before removing session summaries, directories and relation metadata. Rows with foreign session membership or deleted observations are excluded.

## Local private policy

The repository contains only `scripts/blocked-terms.example.json`, with an empty term list. Keep actual terms outside the checkout in `~/.config/engram-reader/blocked-terms.json`, an XDG config directory, or a file selected through `ENGRAM_READER_BLOCKLIST`. Use private filesystem permissions. No client-specific, company-specific or universally mandatory terms are distributed.

Matching normalizes case, Unicode compatibility characters, combining marks, invisible formatting characters and supported confusables. Empty terms are rejected. An empty list matches no text. All textual keys and values are checked before publishing or returning data. A pinned allowlist limits project scope; automatic mode selects eligible projects from the source.

Each refresh and audit compiles the normalized terms into one literal substring matcher and normalizes each inspected field once. The comparison rules and original stored text stay unchanged.

On a failed refresh, the previous snapshot is retained only if it passes the current policy audit. A dirty or unverifiable snapshot is replaced with schema-only data, or removed if its schema cannot be read. A successful refresh publishes `filtered/audit-receipt.json` with SHA-256 hashes of the finalized database and normalized exclusion policy plus exact project allowlist, the reader version, passing counts and audit time. The receipt contains no terms, project names or memory text and has private file permissions.

Startup holds the refresh lock while validating both hashes and the reader version. A matching receipt certifies the exact previously audited snapshot under the current policy. Missing, malformed or mismatched receipts trigger the full audit; a failing audit refuses to launch MCP. SQLite WAL, shared-memory and journal sidecars also require a full audit because their content is outside the main file hash. Publication replaces the database before the receipt, so an interrupted refresh leaves a mismatched receipt that cannot bypass auditing. The receipt relies on the same trusted local state directory as the snapshot and installed reader. The `verify` command always performs the full audit.

Each process receives a disposable copy with cloud autosync disabled and inherited Engram overrides removed.

## HTTP boundaries

OAuth subject and scopes determine tenant access. Request arguments cannot select a tenant, filesystem path or arbitrary SQL. Snapshots are encrypted with per-tenant keys derived from a master key, staged atomically, audited and published with private permissions. Reads run in a separate macOS sandbox process that denies network and filesystem writes and restricts storage reads. The configured private terms travel through stdin; the policy file is not opened by the sandbox.

Upload size, record counts, query length, page size and response bytes are bounded. Account deletion and policy changes cancel reads still in flight. Raw memory text, rejected input and credentials are withheld from error and access logs.

## Limits

Term filtering is a configurable exclusion mechanism, not a semantic guarantee that all sensitive information has been detected. Review the private blocklist and pinned project list before connecting a client. The empty example deliberately contains no deployment-specific policy. Client dialogs, OAuth callbacks and hosted registration must be verified separately with synthetic data.
