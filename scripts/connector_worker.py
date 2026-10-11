"""Sandbox worker: one synthetic filtered snapshot arrives through stdin."""
import json
import resource
import sys
from connector_store import read_tool, validate_export


def main():
    resource.setrlimit(resource.RLIMIT_CPU, (8, 8))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    try:
        message = json.load(sys.stdin)
        if message["operation"] == "validate":
            validate_export(json.dumps(message["export"]).encode(), tuple(message["terms"]))
            result = {"verified": True}
        elif message["operation"] == "read":
            result = read_tool(message["data"], message["name"], message["arguments"], tuple(message["terms"]))
        else:
            return 1
        print(json.dumps(result))
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
