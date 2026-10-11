"""Read-only tenant boundaries for the opt-in local connector."""
from dataclasses import dataclass
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

from cryptography.fernet import Fernet, InvalidToken
import engram_reader as local

POLICY = "private-config-v1"
MAX_UPLOAD = 25 * 1024 * 1024
MAX_RECORDS = 50_000
MAX_RESPONSE = 64 * 1024
TOOL_NAMES = tuple(local.TOOLS.split(","))
FIELDS = {
    "sessions": {"id", "project", "directory", "ownership_mode", "started_at", "ended_at", "summary"},
    "observations": {"id", "sync_id", "session_id", "type", "title", "content", "tool_name", "project",
                     "scope", "topic_key", "revision_count", "duplicate_count", "last_seen_at", "pinned",
                     "created_at", "updated_at", "deleted_at", "review_after", "expires_at"},
    "prompts": {"id", "sync_id", "session_id", "content", "project", "created_at", "source_inbox_id"},
}


class Rejected(ValueError):
    """A boundary failed; callers must never include the input in an error."""


@dataclass(frozen=True)
class Principal:
    subject: str
    scopes: frozenset[str]


def require_scope(principal, scope):
    if not principal.subject or scope not in principal.scopes:
        raise Rejected("access denied")


def validate_export(payload, terms=None):
    terms = tuple(local.load_terms() if terms is None else terms)
    if len(payload) > MAX_UPLOAD:
        raise Rejected("upload too large")
    try:
        doc = json.loads(payload)
        if set(doc) != {"format", "policy", "filter_passed", "data"}:
            raise ValueError()
        if (doc["format"] != "engram-filtered-v1" or doc["policy"] != POLICY
                or doc["filter_passed"] is not True):
            raise ValueError()
        data = doc["data"]
        if set(data) != {"version", "exported_at", "sessions", "observations", "prompts"}:
            raise ValueError()
        if data["version"] != "0.2.0" or not isinstance(data["exported_at"], str):
            raise ValueError()
        groups = [data[k] for k in ("sessions", "observations", "prompts")]
        if any(not isinstance(rows, list) for rows in groups) or sum(map(len, groups)) > MAX_RECORDS:
            raise ValueError()
        sessions = {}
        for kind, rows in zip(("sessions", "observations", "prompts"), groups):
            seen = set()
            for row in rows:
                if (not isinstance(row, dict) or not set(row) <= FIELDS[kind]
                        or any(isinstance(v, (dict, list)) for v in row.values())):
                    raise ValueError()
                if (local.matches(row, terms) or local.matches({k: k for k in row}, terms)
                        or not local.allowed(row.get("project"), terms)):
                    raise ValueError()
                if kind == "sessions" and (row.get("summary") is not None
                        or row.get("directory") not in ("", None)):
                    raise ValueError()
                rid = row.get("id")
                if kind == "sessions":
                    if not isinstance(rid, str) or not rid:
                        raise ValueError()
                    sessions[rid] = row["project"]
                elif type(rid) is not int or rid < 1:
                    raise ValueError()
                elif sessions.get(row.get("session_id")) != row["project"] or row.get("deleted_at"):
                    raise ValueError()
                if rid in seen:
                    raise ValueError()
                seen.add(rid)
                for field in ("title", "content", "topic_key", "created_at"):
                    if field in row and row[field] is not None and not isinstance(row[field], str):
                        raise ValueError()
        return data
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise Rejected("invalid filtered export") from None


def read_tool(data, name, arguments, terms=None):
    fields = {"mem_search": {"query", "project", "limit"},
              "mem_context": {"project", "limit"},
              "mem_get_observation": {"id"}, "mem_timeline": {"id", "limit"},
              "mem_stats": set(), "mem_list_projects": set()}
    if name not in fields or not isinstance(arguments, dict) or set(arguments) - fields[name]:
        raise Rejected("tool or arguments denied")
    limit = arguments.get("limit", 20)
    if type(limit) is not int or not 1 <= limit <= 20:
        raise Rejected("page limit exceeded")
    query = arguments.get("query", "")
    if not isinstance(query, str) or len(query.encode()) > 2048:
        raise Rejected("query limit exceeded")
    project = arguments.get("project")
    if project is not None and not isinstance(project, str):
        raise Rejected("invalid project")
    rid = arguments.get("id")
    if name in ("mem_get_observation", "mem_timeline") and (type(rid) is not int or rid < 1):
        raise Rejected("invalid observation")
    # Recheck the configured policy on every read, including listing and statistics.
    validate_export(json.dumps({"format": "engram-filtered-v1", "policy": POLICY,
                               "filter_passed": True, "data": data}).encode(), terms)
    if name == "mem_stats":
        return {"sessions": len(data["sessions"]), "observations": len(data["observations"]),
                "prompts": len(data["prompts"]), "truncated": False}
    if name == "mem_list_projects":
        records = [{"project": p} for p in sorted({s["project"] for s in data["sessions"]})]
    else:
        records = data["observations"]
        if project is not None:
            records = [r for r in records if r["project"] == project]
        if name == "mem_search":
            records = [r for r in records if query.casefold() in
                       (str(r.get("title", "")) + " " + str(r.get("content", ""))).casefold()]
        elif name == "mem_get_observation":
            records = [r for r in records if r["id"] == rid]
        elif name == "mem_timeline":
            center = next((r for r in records if r["id"] == rid), None)
            records = [] if center is None else [r for r in records if r["session_id"] == center["session_id"]]
        records = sorted(records, key=lambda r: (r.get("created_at") or "", r["id"]), reverse=True)
    result = {"records": records[:limit], "truncated": len(records) > limit}
    while len(json.dumps(result).encode()) > MAX_RESPONSE // 3 and result["records"]:
        result["records"] = result["records"][:-1]
        result["truncated"] = True
    return result



class RateLimited(Rejected):
    pass


def worker_read_roots():
    return {Path(p).resolve() for p in (sys.base_prefix, sys.prefix, Path(__file__).parent,
            "/usr/lib", "/System/Library", "/Library/Apple/System/Library", "/dev", "/private/var/db/dyld")}


def checked_storage_root(root):
    path = Path(root)
    if path.is_symlink():
        raise Rejected("invalid storage root")
    path = path.resolve()
    if any(path.is_relative_to(allowed) or allowed.is_relative_to(path) for allowed in worker_read_roots()):
        raise Rejected("storage overlaps worker read paths")
    return path


def cleanup_stages(root):
    # One service process owns each root. Never follow tenant or stage symlinks.
    for directory in root.iterdir():
        if directory.is_symlink() or not directory.is_dir() or not re.fullmatch(r"[0-9a-f]{64}", directory.name):
            continue
        for stage in directory.glob("stage-*"):
            if stage.is_symlink() or stage.is_file():
                stage.unlink()
            elif stage.is_dir():
                shutil.rmtree(stage)


def sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class TenantStore:
    """Encrypted snapshots; atomic replacement has no mutable shared read cache.

    Data-only staging and reads run in separate macOS sandbox processes.
    A hosted identity provider and production namespaces remain release gates.
    """
    def __init__(self, root, master_key, upload_interval=900):
        if len(master_key) < 32:
            raise Rejected("storage key unavailable")
        self.root = checked_storage_root(root)
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.master_key = master_key
        self.upload_interval = upload_interval
        self.policy = POLICY
        self.lock = threading.RLock()
        self.uploaded = {}
        cleanup_stages(self.root)

    def tenant_key(self, subject):
        return base64.urlsafe_b64encode(hmac.digest(self.master_key, b"key:" + subject.encode(), "sha256"))

    def directory(self, subject):
        digest = hmac.new(self.master_key, b"directory:" + subject.encode(), hashlib.sha256).hexdigest()
        directory = self.root / digest
        if directory.is_symlink():
            raise Rejected("invalid tenant storage")
        directory.mkdir(mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        return directory

    def active(self, principal):
        directory = self.directory(principal.subject)
        if (directory / "deleted").exists():
            raise Rejected("account unavailable")
        return directory

    def snapshot(self, principal):
        require_scope(principal, "engram:read")
        with self.lock:
            directory = self.active(principal)
            if self.policy != POLICY:
                raise Rejected("fresh policy required")
            path = directory / "snapshot.enc"
            if path.is_symlink():
                raise Rejected("invalid snapshot")
            if not path.exists():
                return {"version": "0.2.0", "exported_at": "", "sessions": [], "observations": [], "prompts": []}
            ciphertext = path.read_bytes()
        try:
            return validate_export(Fernet(self.tenant_key(principal.subject)).decrypt(ciphertext))
        except InvalidToken:
            raise Rejected("snapshot unavailable") from None

    def upload(self, principal, payload):
        require_scope(principal, "engram:upload")
        # Strict data-only schema: no SQL, file paths, archives or native importer.
        validate_export(payload)
        with self.lock:
            directory = self.active(principal)
            if self.policy != POLICY:
                raise Rejected("fresh policy required")
            if time.monotonic() - self.uploaded.get(principal.subject, -1e10) < self.upload_interval:
                raise RateLimited("upload rate exceeded")
            with tempfile.TemporaryDirectory(prefix="stage-", dir=directory) as scratch:
                stage = Path(scratch) / "snapshot.enc"
                stage.write_bytes(Fernet(self.tenant_key(principal.subject)).encrypt(payload))
                os.chmod(stage, 0o600)
                # Verify the staged bytes before publication, not just the input.
                checked = Fernet(self.tenant_key(principal.subject)).decrypt(stage.read_bytes())
                validate_export(checked)
                restricted_worker({"operation": "validate", "export": json.loads(checked)}, self.root)
                with stage.open("rb") as stream:
                    os.fsync(stream.fileno())
                os.replace(stage, directory / "snapshot.enc")
                sync_directory(directory)
            self.uploaded[principal.subject] = time.monotonic()
        return {"published": True, "policy": POLICY}

    def call(self, principal, name, arguments):
        result = restricted_worker({"operation": "read", "data": self.snapshot(principal),
                                    "name": name, "arguments": arguments}, self.root)
        # A policy change or deletion also cancels an already-running read.
        with self.lock:
            self.active(principal)
            if self.policy != POLICY:
                raise Rejected("fresh policy required")
        return result

    def delete(self, principal):
        require_scope(principal, "engram:account")
        with self.lock:
            directory = self.active(principal)
            marker = directory / "deleted"
            marker.touch(mode=0o600)
            (directory / "snapshot.enc").unlink(missing_ok=True)
            self.uploaded.pop(principal.subject, None)



def worker_command(storage_root=None):
    """OS policy allows interpreter/code reads, never store files or networking."""
    sandbox = Path("/usr/bin/sandbox-exec")
    if sys.platform != "darwin" or not sandbox.is_file():
        raise Rejected("local macOS worker sandbox required")
    permitted = {str(path) for path in worker_read_roots()}
    rules = " ".join("(subpath " + json.dumps(p) + ")" for p in sorted(permitted))
    blocked = " ".join("(subpath " + json.dumps(p) + ")" for p in
                       ("/Users", "/private/var/folders", "/var/folders", "/private/tmp", "/tmp", "/Volumes", "/opt"))
    if storage_root is not None:
        # Reuse the constructor boundary even when this helper is called directly.
        blocked += " (subpath " + json.dumps(str(checked_storage_root(storage_root))) + ")"
    profile = "(version 1)(allow default)(deny network*)(deny file-write*)(deny file-read-data " + blocked + ")(allow file-read-data " + rules + ")"
    return [str(sandbox), "-p", profile, sys.executable, "-B", str(Path(__file__).with_name("connector_worker.py"))]


def restricted_worker(message, storage_root=None):
    message = {**message, "terms": list(local.load_terms())}
    result = subprocess.run(worker_command(storage_root), input=json.dumps(message).encode(), capture_output=True,
                            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}, timeout=10)
    if result.returncode:
        raise Rejected("worker request denied")
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise Rejected("worker response unavailable") from None
