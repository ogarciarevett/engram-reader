#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
READ_CLI_ONLY=0
if [ "${1-}" = "--read-cli-only" ]; then
    [ "$#" -eq 1 ] || exit 1
    READ_CLI_ONLY=1
fi
python3 - "$SCRIPT_DIR" <<'PY'
import os
from pathlib import Path
import shlex
import shutil
import sys
os.umask(0o077)
source = Path(sys.argv[1])
state = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "engram-reader"
state.mkdir(parents=True, exist_ok=True, mode=0o700)
for name in ("engram_reader_read.py", "engram_reader.py", "blocked-terms.example.json"):
    shutil.copy2(source / name, state / name)
    os.chmod(state / name, 0o600)
bindir = Path.home() / ".local/bin"
bindir.mkdir(parents=True, exist_ok=True)
for name, script, arguments in (("engram-reader", "engram_reader_read.py", ''),
                                ("engram-reader-mcp", "engram_reader.py", ' mcp')):
    wrapper = bindir / name
    wrapper.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -B "
                       + shlex.quote(str(state / script)) + arguments + ' "$@"\n')
    os.chmod(wrapper, 0o700)
print("Reader and MCP launchers installed.")
PY
if [ "$READ_CLI_ONLY" -eq 1 ]; then
    exit 0
fi
exec python3 "$SCRIPT_DIR/engram_reader.py" "$@" install
