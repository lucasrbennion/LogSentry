# test_parser.py — verifies that parse_file correctly reads and interprets the
# bundled sample Windows event log file (backend/data/sample_windows_logs.txt).
#
# Run directly with: python test_parser.py
# Expected output: "All parsey.py tests passed." followed by a results table.

from pathlib import Path
import sys

# Add the backend directory to sys.path so Python can find parser.py
# (the test lives one level deeper in tests/, not in backend/ itself).
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from parser import parse_file

sample = BACKEND_DIR / "data" / "sample_windows_logs.txt"
results = parse_file(sample)

# The sample file contains exactly three log records — confirm nothing was lost or duplicated.
assert len(results) == 3

# Record 0 should be a privileged-logon event (4672) for the 'labadmin' account.
assert results[0]["event_id"] == 4672
assert results[0]["subject_account"] == "labadmin"

# Record 1 should be a failed logon (4625) for 'testuser1' with a wrong-password reason.
assert results[1]["event_id"] == 4625
assert results[1]["target_account"] == "testuser1"
assert results[1]["failure_reason"] == "Unknown user name or bad password."

# Record 2 should be a successful interactive logon (4624) for 'testuser1'.
# Logon type "2" means the user typed credentials directly at the keyboard/console.
assert results[2]["event_id"] == 4624
assert results[2]["new_logon_account"] == "testuser1"
assert results[2]["logon_type"] == "2"


def print_table(rows):
    """Print the parsed events as a simple fixed-width table for visual inspection.

    Columns with no data across any row are hidden to keep the output readable.
    Values longer than MAX_W characters are truncated with a trailing '~'.
    """
    skip = {"raw_record", "privileges"}  # these fields are too long / not useful in a table
    keys = [k for k in rows[0] if k not in skip]
    # Only show columns that have at least one non-None value.
    active = [k for k in keys if any(r.get(k) is not None for r in rows)]

    MAX_W = 35  # maximum column width in characters
    widths = {
        k: min(max(len(k), max(len(str(r.get(k) or "")) for r in rows)), MAX_W)
        for k in active
    }

    def cell(val, w):
        """Format a single cell value, truncating if it exceeds the column width."""
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
