from pathlib import Path
import sys

#These two lines make the backend directory importable so the test can find parser.py
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from parser import parse_file

sample = BACKEND_DIR / "data" / "sample_windows_logs.txt"
results = parse_file(sample)

assert len(results) == 3

assert results[0]["event_id"] == 4672
assert results[0]["subject_account"] == "labadmin"

assert results[1]["event_id"] == 4625
assert results[1]["target_account"] == "testuser1"
assert results[1]["failure_reason"] == "Unknown user name or bad password."

assert results[2]["event_id"] == 4624
assert results[2]["new_logon_account"] == "testuser1"
assert results[2]["logon_type"] == "2"

def print_table(rows):
    skip = {"raw_record", "privileges"}
    keys = [k for k in rows[0] if k not in skip]
    active = [k for k in keys if any(r.get(k) is not None for r in rows)]

    MAX_W = 35
    widths = {k: min(max(len(k), max(len(str(r.get(k) or "")) for r in rows)), MAX_W) for k in active}

    def cell(val, w):
        s = str(val) if val is not None else ""
        return (s[:w - 1] + "~") if len(s) > w else s.ljust(w)

    sep = "-+-".join("-" * widths[k] for k in active)
    header = " | ".join(k.ljust(widths[k]) for k in active)
    print(header)
    print(sep)
    for r in rows:
        print(" | ".join(cell(r.get(k), widths[k]) for k in active))

print("All parsey.py tests passed.")
print_table(results)
