#!/usr/bin/env python3
"""Build a privacy-filtered, read-only Engram MCP snapshot."""
import argparse
import contextlib
import fcntl
import functools
import hashlib
import json
import itertools
import os
from pathlib import Path
import plistlib
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unicodedata

DEFAULT_TERMS = ()
VERSION = "0.2.0"
LABEL = "local.engram-reader.refresh"
TOOLS = "mem_search,mem_context,mem_get_observation,mem_timeline,mem_stats,mem_list_projects"
DEFAULT_STATE = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "engram-reader"


# Greek/Cyrillic mappings for the comparison alphabet, from Unicode confusables 18.0.0:
# https://www.unicode.org/Public/security/latest/confusables.txt
# Collapse the ambiguous i/l shapes conservatively for filter comparisons only.
CONFUSABLES = str.maketrans({
    **dict.fromkeys("αа", "a"), **dict.fromkeys("𐆋ԁ", "d"),
    **dict.fromkeys("еҽε", "e"), **dict.fromkeys("iıιіꙇӏ𝈪", "l"),
    **dict.fromkeys("ρϸр", "p"), **dict.fromkeys("ᴦг𝈖", "r"),
    "ѕ": "s", **dict.fromkeys("хχ", "x"),
})


def filter_text(value):
    """Comparison only; stored text and tenant/project identifiers stay intact."""
    value = unicodedata.normalize("NFKC", value)
    value = "".join(ch for ch in value if unicodedata.category(ch) != "Cf").casefold()
    # Dotted I and diacritic insertions must not hide the configured terms.
    value = "".join(ch for ch in unicodedata.normalize("NFD", value)
                    if unicodedata.category(ch) not in ("Mn", "Me"))
    return value.translate(CONFUSABLES)


def allowed(name, terms=None):
    if not isinstance(name, str):
        return False
    normalized = filter_text(name)
    return bool(normalized.strip()) and not compile_terms(terms).search(normalized, filter_text("project"))


def blocklist_path():
    """Resolve the private policy without consulting checkout or state files."""
    explicit = os.environ.get("ENGRAM_READER_BLOCKLIST")
    if explicit is not None:
        if not explicit.strip():
            raise ValueError("invalid blocked term configuration")
        return Path(explicit).expanduser()
    root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return root / "engram-reader" / "blocked-terms.json"


def load_terms(state=None):
    """Load local private terms; the public distribution has an empty default."""
    path = blocklist_path()
    if path.is_symlink():
        raise ValueError("invalid blocked term configuration")
    if not path.exists():
        if "ENGRAM_READER_BLOCKLIST" in os.environ:
            raise ValueError("private blocked term configuration unavailable")
        return ()
    config = json.loads(path.read_text())
    terms = config.get("terms") if isinstance(config, dict) else None
    if not isinstance(terms, list) or not all(isinstance(t, str) and filter_text(t).strip() for t in terms):
        raise ValueError("invalid blocked term configuration")
    return tuple(sorted({t.strip().casefold() for t in terms}))


class TermMatcher:
    """One literal substring matcher over the unchanged comparison alphabet."""
    def __init__(self, terms):
        self.terms = tuple(sorted({filter_text(term) for term in terms}))
        self.pattern = re.compile("|".join(re.escape(term) for term in self.terms)) if self.terms else None

    def search(self, *values):
        return self.pattern is not None and any(self.pattern.search(value) for value in values)


@functools.lru_cache(maxsize=16)
def cached_matcher(terms):
    return TermMatcher(terms)


def compile_terms(terms=None):
    if isinstance(terms, TermMatcher):
        return terms
    return cached_matcher(tuple(load_terms() if terms is None else terms))


def operation_matchers(terms):
    # A compiled policy is frozen by refresh/startup. Legacy callers may supply
    # separate row terms; their project checks still use the local blocklist.
    if isinstance(terms, TermMatcher):
        return terms, terms
    projects = compile_terms()
    return (projects if terms is None else compile_terms(terms)), projects


def matches(row, terms=None):
    pattern = compile_terms(terms).pattern
    return pattern is not None and any(pattern.search(filter_text(value))
               for value in itertools.chain(row.keys(), row.values()) if isinstance(value, str))


def write_json(path, value):
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as f:
        json.dump(value, f, indent=2)
        f.write("\n")
        temp = Path(f.name)
    os.replace(temp, path)


def connect(path):
    if not path.is_file() or path.is_symlink():
        raise ValueError("database must be an existing regular file")
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)


def environment(data_dir):
    # Do not inherit cloud tokens, project overrides, or other Engram routing.
    env = {k: v for k, v in os.environ.items() if not k.startswith("ENGRAM_")}
    env.update(ENGRAM_DATA_DIR=str(data_dir), ENGRAM_CLOUD_AUTOSYNC="0")
    return env


def run_engram(binary, directory, *args):
    result = subprocess.run([binary, *args], env=environment(directory),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    if result.returncode:
        raise RuntimeError("Engram operation failed; output withheld")


def require_version(binary, directory):
    result = subprocess.run([binary, "version"], env=environment(directory),
                            capture_output=True, text=True, timeout=10)
    if result.returncode or result.stdout.strip() != "engram 3.3.2":
        raise ValueError("this integration requires Engram v3.3.2")


def projects(source, terms=None):
    terms = compile_terms(terms)
    with contextlib.closing(connect(source / "engram.db")) as db:
        rows = db.execute("SELECT project FROM observations UNION SELECT project FROM sessions "
                          "UNION SELECT project FROM user_prompts")
        return sorted({row[0] for row in rows if allowed(row[0], terms)})


def export_selected(source, names, terms=None):
    """Export approved rows through a read-only connection, including legacy labels."""
    terms, project_terms = operation_matchers(terms)
    with contextlib.closing(connect(source / "engram.db")) as db:
        db.row_factory = sqlite3.Row
        db.create_function("permitted", 1, lambda name: int(allowed(name, project_terms) and name in names))
        db.execute("BEGIN")
        # Inspect original columns before redaction, including future text fields.
        sessions = [{key: row[key] for key in ("id", "project", "directory", "ownership_mode",
                                              "started_at", "ended_at", "summary")}
                    for row in db.execute("SELECT * FROM sessions WHERE permitted(project)")
                    if not matches(dict(row), terms)]
        obs_columns = ("id,sync_id,session_id,type,title,content,tool_name,project,scope,topic_key,"
                       "revision_count,duplicate_count,last_seen_at,pinned,created_at,updated_at,"
                       "deleted_at,review_after,expires_at")
        observations = [{key: row[key] for key in obs_columns.split(",")}
                        for row in db.execute(
            "SELECT o.* FROM observations o JOIN sessions s ON s.id=o.session_id "
            "WHERE permitted(s.project) AND permitted(coalesce(nullif(o.project,''),s.project)) "
            "AND o.deleted_at IS NULL") if not matches(dict(row), terms)]
        for row in observations:
            row["pinned"] = bool(row["pinned"])
        prompts = [{key: row[key] for key in ("id", "sync_id", "session_id", "content", "project",
                                            "created_at", "source_inbox_id")}
                   for row in db.execute(
            "SELECT p.* FROM user_prompts p JOIN sessions s ON s.id=p.session_id "
            "WHERE permitted(s.project) AND permitted(coalesce(nullif(p.project,''),s.project))")
                   if not matches(dict(row), terms)]
        return sanitize({"version": "0.2.0", "exported_at": "", "sessions": sessions,
                         "observations": observations, "prompts": prompts}, names, terms, project_terms)


def sanitize(data, names, terms=None, project_terms=None):
    """Drop foreign session closure, deleted rows, summaries and relation metadata."""
    terms, local_projects = operation_matchers(terms)
    project_terms = local_projects if project_terms is None else project_terms
    sessions = {s["id"]: {**s, "summary": None, "directory": ""}
                for s in data.get("sessions") or []
                if s.get("project") in names and allowed(s.get("project"), project_terms) and not matches(s, terms)}
    out = {"version": data["version"], "exported_at": data["exported_at"],
           "sessions": list(sessions.values()), "observations": [], "prompts": []}
    for kind in ("observations", "prompts"):
        for row in data.get(kind) or []:
            session = sessions.get(row.get("session_id"))
            if session is None or row.get("deleted_at") or matches(row, terms):
                continue
            owner = row.get("project") or session["project"]
            if owner in names and allowed(owner, project_terms):
                out[kind].append({**row, "project": owner})
    return out


def audit(path, names, terms=None):
    with contextlib.closing(connect(path)) as db:
        tables = ("sessions", "observations", "user_prompts")
        counts = {table: db.execute("SELECT count(*) FROM " + table).fetchone()[0] for table in tables}
        # Schema-only cleanup contains no text or membership to check, even if
        # the private policy is unavailable (the previous audit behaved so too).
        if not any(counts.values()):
            return {**counts, "excluded_rows": 0, "matching_rows": 0}
        terms, project_terms = operation_matchers(terms)
        db.row_factory = sqlite3.Row
        db.create_function("permitted", 1, lambda name: int(allowed(name, project_terms) and name in names))
        for table in tables:
            if db.execute("SELECT count(*) FROM " + table + " WHERE NOT permitted(project)").fetchone()[0]:
                raise ValueError("filtered database contains an unapproved project")
            if any(matches(dict(row), terms) for row in db.execute("SELECT * FROM " + table)):
                raise ValueError("filtered database contains excluded text")
        for table in ("observations", "user_prompts"):
            if db.execute("SELECT count(*) FROM " + table + " r LEFT JOIN sessions s "
                          "ON s.id=r.session_id WHERE s.id IS NULL OR NOT permitted(s.project)").fetchone()[0]:
                raise ValueError("filtered database contains foreign session membership")
    counts["excluded_rows"] = 0
    counts["matching_rows"] = 0
    return counts


def load_policy(state, source, terms=None):
    terms = compile_terms(terms)
    path = state / "allowed-projects.json"
    config = json.loads(path.read_text()) if path.exists() else {"mode": "auto", "projects": []}
    if config.get("mode") == "auto":
        config["projects"] = projects(source, terms)
    elif config.get("mode") != "pinned":
        raise ValueError("policy mode must be auto or pinned")
    names = config["projects"]
    if not isinstance(names, list) or not all(allowed(name, terms) for name in names):
        raise ValueError("allowlist contains an invalid or excluded project")
    config["projects"] = sorted(set(names))
    write_json(path, config)
    return set(config["projects"])


def snapshot_hash(path):
    if not path.is_file() or path.is_symlink():
        raise ValueError("database must be an existing regular file")
    digest = hashlib.sha256()
    with path.open("rb") as snapshot:
        for chunk in iter(lambda: snapshot.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def policy_hash(names, terms):
    # Project identifiers are exact SQLite identities, not comparison text.
    policy = {"terms": compile_terms(terms).terms, "projects": sorted(names)}
    return hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def write_receipt(path, names, terms, counts):
    write_json(path.parent / "audit-receipt.json", {
        "snapshot_sha256": snapshot_hash(path), "policy_sha256": policy_hash(names, terms),
        "reader_version": VERSION, "counts": counts, "audited_at": int(time.time())})


def valid_receipt(path, names, terms):
    # SQLite may expose WAL or journal content absent from the main file's hash.
    if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
        return False
    receipt_path = path.parent / "audit-receipt.json"
    try:
        if receipt_path.is_symlink():
            return False
        receipt = json.loads(receipt_path.read_text())
        counts = receipt["counts"]
        fields = ("sessions", "observations", "user_prompts", "excluded_rows", "matching_rows")
        return (receipt["reader_version"] == VERSION
                and all(type(counts[key]) is int and counts[key] >= 0 for key in fields)
                and counts["excluded_rows"] == counts["matching_rows"] == 0
                and type(receipt["audited_at"]) is int and receipt["audited_at"] > 0
                and receipt["policy_sha256"] == policy_hash(names, terms)
                and receipt["snapshot_sha256"] == snapshot_hash(path))
    except (OSError, ValueError, KeyError, TypeError):
        return False


def empty_published(filtered):
    """Replace unsafe data with schema only; no memory content is copied."""
    (filtered / "audit-receipt.json").unlink(missing_ok=True)
    path = filtered / "engram.db"
    if not path.exists():
        return
    try:
        with contextlib.closing(connect(path)) as db:
            schema = list(db.execute("SELECT type,name,sql FROM sqlite_master "
                                     "WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' "
                                     "ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END"))
            version = db.execute("PRAGMA user_version").fetchone()[0]
        virtual = [name for kind, name, sql in schema if "CREATE VIRTUAL TABLE" in sql.upper()]
        with tempfile.TemporaryDirectory(prefix="empty-", dir=filtered.parent) as scratch:
            blank = Path(scratch) / "engram.db"
            with contextlib.closing(sqlite3.connect(blank)) as db:
                for kind, name, sql in schema:
                    if not any(name.startswith(prefix + "_") for prefix in virtual):
                        db.execute(sql)
                db.execute("PRAGMA user_version=" + str(version))
                db.commit()
            os.chmod(blank, 0o600)
            os.replace(blank, path)
    except Exception:
        # An unreadable database cannot be certified; absence is the safe fallback.
        path.unlink(missing_ok=True)
    for suffix in ("-wal", "-shm", "-journal"):
        Path(str(path) + suffix).unlink(missing_ok=True)


def refresh(state):
    with (state / "refresh.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        names = terms = None
        try:
            terms = compile_terms(load_terms(state))
            config = json.loads((state / "allowed-projects.json").read_text())
            names = set(config["projects"])
        except FileNotFoundError:
            pass  # Initial installation has no published snapshot or project policy.
        except Exception:
            empty_published(state / "filtered")
            (state / "verification.json").unlink(missing_ok=True)
            raise
        try:
            return rebuild(state, terms)
        except Exception:
            try:
                if names is None or terms is None:
                    raise ValueError("snapshot policy unavailable")
                audit(state / "filtered/engram.db", names, terms)
            except Exception:
                empty_published(state / "filtered")
                (state / "verification.json").unlink(missing_ok=True)
            raise


def rebuild(state, terms):
    config = json.loads((state / "installation.json").read_text())
    source = Path(config["source"])
    require_version(config["engram"], state)
    if source.resolve() == (state / "filtered").resolve() or source.resolve() == state.resolve():
        raise ValueError("source and destination must be separate")
    terms = compile_terms(load_terms(state) if terms is None else terms)
    # The caller holds the refresh lock for publication and failure cleanup.
    names = load_policy(state, source, terms)
    filtered = state / "filtered"
    filtered.mkdir(mode=0o700, exist_ok=True)
    # Rebuild from scratch so source deletions and allowlist changes propagate.
    with tempfile.TemporaryDirectory(prefix="refresh-", dir=state) as scratch:
        work = Path(scratch)
        fresh = work / "store"
        fresh.mkdir(mode=0o700)
        run_engram(config["engram"], fresh, "version")
        export = work / "export.json"
        write_json(export, export_selected(source, names, terms))
        run_engram(config["engram"], fresh, "import", str(export))
        export.unlink()
        counts = audit(fresh / "engram.db", names, terms)
        # No server opens this published file for writes; servers use private copies.
        with contextlib.closing(sqlite3.connect(fresh / "engram.db")) as db:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            db.execute("PRAGMA journal_mode=DELETE")
        os.chmod(fresh / "engram.db", 0o600)
        write_receipt(fresh / "engram.db", names, terms, counts)
        os.replace(fresh / "engram.db", filtered / "engram.db")
        os.replace(fresh / "audit-receipt.json", filtered / "audit-receipt.json")
    write_json(state / "verification.json", {**counts, "refreshed_at": int(time.time()),
                                            "project_count": len(names), "registered": False})
    return counts


def install(state, source, binary):
    require_version(binary, state)
    state.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(state, 0o700)
    write_json(state / "installation.json", {"source": str(source.resolve()), "engram": binary})
    counts = refresh(state)
    installed_script = state / "engram_reader.py"
    if Path(__file__).resolve() != installed_script.resolve():
        shutil.copy2(__file__, installed_script)
        shutil.copy2(Path(__file__).with_name("blocked-terms.example.json"),
                     state / "blocked-terms.example.json")
    os.chmod(state / "blocked-terms.example.json", 0o600)
    os.chmod(installed_script, 0o600)
    # A generic client configuration for the installed stdio transport.
    write_json(state / "mcp-candidate.json", {"mcpServers": {"engram": {
        "command": sys.executable, "args": [str(installed_script), "--state", str(state), "mcp"],
        "env": {"ENGRAM_DATA_DIR": str(state / "filtered"), "ENGRAM_CLOUD_AUTOSYNC": "0"}}}})
    agent = Path.home() / "Library/LaunchAgents" / (LABEL + ".plist")
    agent.parent.mkdir(parents=True, exist_ok=True)
    plist = {"Label": LABEL, "ProgramArguments": [sys.executable, str(installed_script),
             "--state", str(state), "refresh"], "StartInterval": 900, "RunAtLoad": True,
             "StandardOutPath": str(state / "refresh.log"), "StandardErrorPath": str(state / "refresh.log"),
             "Umask": 0o077}
    payload = plistlib.dumps(plist)
    domain = "gui/" + str(os.getuid())
    loaded = subprocess.run(["launchctl", "print", domain + "/" + LABEL],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    changed = not agent.exists() or agent.read_bytes() != payload
    if changed:
        if loaded:
            subprocess.run(["launchctl", "bootout", domain + "/" + LABEL], check=True)
        agent.write_bytes(payload)
        os.chmod(agent, 0o600)
    if changed or not loaded:
        subprocess.run(["launchctl", "bootstrap", domain, str(agent)], check=True)
    print(json.dumps({**counts, "registered": False, "status": "installed"}))
    return 0


def mcp(state):
    config = json.loads((state / "installation.json").read_text())
    require_version(config["engram"], state)
    # Take a verified, private snapshot under the refresh lock, then release it.
    with tempfile.TemporaryDirectory(prefix="mcp-", dir=state) as scratch:
        directory = Path(scratch)
        with (state / "refresh.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            policy = json.loads((state / "allowed-projects.json").read_text())
            names = set(policy["projects"])
            terms = compile_terms(load_terms(state))
            if not all(allowed(name, terms) for name in names):
                raise ValueError("invalid project policy")
            if not valid_receipt(state / "filtered/engram.db", names, terms):
                audit(state / "filtered/engram.db", names, terms)
            with contextlib.closing(connect(state / "filtered/engram.db")) as src:
                with contextlib.closing(sqlite3.connect(directory / "engram.db")) as dest:
                    src.backup(dest)
        return subprocess.call([config["engram"], "mcp", "--tools=" + TOOLS,
                                "--project", "reader-filtered"], env=environment(directory), cwd=directory,
                               stderr=subprocess.DEVNULL)


def uninstall(state):
    agent = Path.home() / "Library/LaunchAgents" / (LABEL + ".plist")
    subprocess.run(["launchctl", "bootout", "gui/" + str(os.getuid()) + "/" + LABEL],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    agent.unlink(missing_ok=True)
    # Retain allowlist and filtered data for inspection; disable the candidate.
    (state / "mcp-candidate.json").unlink(missing_ok=True)
    print("Refresh uninstalled; private state retained.")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--source", type=Path, default=Path.home() / ".engram")
    parser.add_argument("--engram", default=shutil.which("engram"))
    parser.add_argument("action", choices=["install", "refresh", "verify", "mcp", "uninstall"])
    args = parser.parse_args()
    try:
        if args.action == "install":
            return install(args.state, args.source, args.engram)
        if args.action == "refresh":
            print(json.dumps(refresh(args.state)))
        elif args.action == "verify":
            names = set(json.loads((args.state / "allowed-projects.json").read_text())["projects"])
            print(json.dumps(audit(args.state / "filtered/engram.db", names, load_terms(args.state))))
        elif args.action == "mcp":
            return mcp(args.state)
        else:
            uninstall(args.state)
    except Exception:
        # Export/import exceptions can contain memory text. Never log their payload.
        print("Operation failed; memory and configuration details withheld.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
