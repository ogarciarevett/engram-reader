import json
import os
from pathlib import Path
import tempfile


def enable_policy():
    scratch = tempfile.TemporaryDirectory()
    old = os.environ.get("ENGRAM_READER_BLOCKLIST")
    path = Path(scratch.name) / "blocked-terms.json"
    path.write_text(json.dumps({"terms": ["filter-alpha", "filter-beta", "restricted"]}))
    os.environ["ENGRAM_READER_BLOCKLIST"] = str(path)

    def cleanup():
        if old is None:
            os.environ.pop("ENGRAM_READER_BLOCKLIST", None)
        else:
            os.environ["ENGRAM_READER_BLOCKLIST"] = old
        scratch.cleanup()
    return cleanup
