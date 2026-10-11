#!/usr/bin/env python3
"""Produce a local filtered JSON export; this command has no network operation."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import sys
import tempfile

import engram_reader as local
from connector_store import POLICY, validate_export


@contextlib.contextmanager
def filtered_file(source, state):
    # An explicit policy is mandatory here, unlike initial local installation.
    policy_path = local.blocklist_path()
    if not policy_path.is_file() or policy_path.is_symlink():
        raise ValueError("private policy unavailable")
    terms = local.load_terms(state)
    config = json.loads((state / "allowed-projects.json").read_text())
    names = config.get("projects")
    if config.get("mode") != "pinned" or not isinstance(names, list) or not all(local.allowed(n) for n in names):
        raise ValueError("explicit pinned project policy required")
    data = local.export_selected(source, set(names), terms)
    doc = {"format": "engram-filtered-v1", "policy": POLICY, "filter_passed": True, "data": data}
    payload = json.dumps(doc).encode()
    validate_export(payload)
    with tempfile.TemporaryDirectory(prefix="export-", dir=state) as scratch:
        path = Path(scratch) / "filtered.json"
        path.write_bytes(payload)
        os.chmod(path, 0o600)
        yield path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--policy-state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        # Refuse to overwrite any existing file, especially a source database.
        with filtered_file(args.source, args.policy_state) as path:
            with args.output.open("xb") as output:
                output.write(path.read_bytes())
        print("Filtered export written locally; remove it after use.")
    except Exception:
        print("Export failed; details withheld.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
