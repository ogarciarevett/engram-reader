#!/usr/bin/env python3
"""Read approved observations from the published filtered snapshot only."""
import argparse
import contextlib
import json
from pathlib import Path
import re
import sqlite3
import sys

sys.dont_write_bytecode = True
from engram_reader import DEFAULT_STATE, filter_text, load_terms, matches


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes rejected arguments, which can be private text.
        raise ValueError("invalid arguments")


def bounded_number(maximum):
    def parse(value):
        if not re.fullmatch(r"[0-9]{1,19}", value) or not 1 <= int(value) <= maximum:
            raise ValueError("invalid number")
        return int(value)
    return parse


def bounded_text(value, maximum):
    if not value.strip() or len(value) > maximum or any(ord(ch) < 32 for ch in value):
        raise ValueError("invalid text")
    return value


def arguments(argv):
    parser = SafeParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=SafeParser)
    search = commands.add_parser("search", allow_abbrev=False)
    search.add_argument("words", nargs="+")
    search.add_argument("--project")
    show = commands.add_parser("show", allow_abbrev=False)
    show.add_argument("id", type=bounded_number(2**63 - 1))
    for name in ("recent", "plans"):
        command = commands.add_parser(name, allow_abbrev=False)
        command.add_argument("hours", nargs="?", default=24, type=bounded_number(168))
        command.add_argument("--limit", default=20, type=bounded_number(50))
    search.add_argument("--limit", default=20, type=bounded_number(50))
    args = parser.parse_args(argv)
    if args.command == "search":
        if len(args.words) > 16 or sum(map(len, args.words)) > 1024:
            raise ValueError("query too long")
        args.words = [filter_text(bounded_text(word, 128)) for word in args.words]
        if any(not word.strip() for word in args.words):
            raise ValueError("empty query")
        if args.project is not None:
            bounded_text(args.project, 256)
    return args


def connect(state):
    # There is deliberately no CLI, environment or installation-config DB override.
    directory = state / "filtered"
    path = directory / "engram.db"
    if state.is_symlink() or directory.is_symlink() or path.is_symlink() or not path.is_file():
        raise ValueError("snapshot unavailable")
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)


def policy(state):
    config = json.loads((state / "allowed-projects.json").read_text())
    names = config.get("projects") if isinstance(config, dict) else None
    if not isinstance(names, list) or not all(isinstance(name, str) and name.strip() for name in names):
        raise ValueError("invalid policy")
    return set(names)


def plan_rank(row):
    title = filter_text(row["title"] or "")
    for rank, prefix in enumerate(("blocker/", "ask-owner/", "decision/", "handoff/", "status/")):
        if title.startswith(filter_text(prefix)):
            if prefix == "ask-owner/" and re.search(r"\bresolved\b", filter_text(
                    title + " " + (row["content"] or ""))):
                return None
            return rank
    return None


def read(args, state):
    names, terms = policy(state), load_terms(state)
    conditions, parameters = ["deleted_at IS NULL"], []
    if args.command == "show":
        conditions.append("id = ?")
        parameters.append(args.id)
    elif args.command == "search":
        for word in args.words:
            conditions.append("instr(search_text(coalesce(title,'') || ' ' || coalesce(content,'')), ?) > 0")
            parameters.append(word)
        if args.project is not None:
            conditions.append("project = ?")
            parameters.append(args.project)
    else:
        conditions.extend(["julianday(updated_at) >= julianday('now', ?)",
                           "julianday(updated_at) <= julianday('now')"])
        parameters.append("-" + str(args.hours) + " hours")
        if args.command == "plans":
            conditions.append("project = ?")
            parameters.append("coordination")
    records, withheld = [], 0
    with contextlib.closing(connect(state)) as db:
        db.row_factory = sqlite3.Row
        db.create_function("search_text", 1, filter_text)
        rows = db.execute("SELECT * FROM observations WHERE " + " AND ".join(conditions)
                          + " ORDER BY julianday(updated_at) DESC, id DESC", parameters)
        for row in rows:
            if row["project"] not in names or matches(dict(row), terms):
                withheld += 1
                continue
            rank = plan_rank(row) if args.command == "plans" else 0
            if rank is None:
                continue
            record = {key: row[key] for key in ("id", "project", "type", "title", "updated_at")}
            full = args.command == "show"
            record["content" if full else "snippet"] = (row["content"] or "")[:20000 if full else 300]
            rendered = json.dumps(record, ensure_ascii=False)
            if matches({"output": rendered}, terms):
                withheld += 1
                continue
            records.append((rank, rendered))
    # Stable sort preserves newest-first order within each urgency class.
    records.sort(key=lambda item: item[0])
    limit = 1 if args.command == "show" else args.limit
    lines = [rendered for _, rendered in records[:limit]]
    if args.command == "show" and not lines:
        lines.append("not found")
    return "\n".join([*lines, "withheld: " + str(withheld)]) + "\n"


def main(argv=None, *, state=None):
    try:
        args = arguments(argv)
    except ValueError:
        print("Invalid arguments; output withheld.", file=sys.stderr)
        return 2
    try:
        # Buffer the result so a later corrupt row cannot leak partial memory output.
        output = read(args, DEFAULT_STATE if state is None else Path(state))
    except Exception:
        print("Read failed; output withheld.", file=sys.stderr)
        return 1
    print(output, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
