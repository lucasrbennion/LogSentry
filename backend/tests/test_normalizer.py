# test_normalizer.py — spot-checks that the normaliser correctly extracts
# the logon_type field from a failed-logon (4625) event.
#
# This is a focused regression test added after logon_type was found to be
# missing from the normalised output in some edge cases.
#
# Run directly with: python test_normalizer.py

from pathlib import Path
import sys

# Add the backend directory to sys.path so Python can find parser.py
# (the test lives one level deeper in tests/, not in backend/ itself).
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from parser import parse_file

sample = Path(__file__).resolve().parents[1] / "data" / "sample_windows_logs.txt"
results = parse_file(sample)

# Find the failed-logon record (event ID 4625) in the parsed results.
# next() will raise StopIteration if no such record exists, which would
# cause the test to fail with a clear error rather than a silent pass.
failed = next(r for r in results if r["event_id"] == 4625)

# Dump the full record so the developer can see all normalised fields at a glance.
print(failed)

# Confirm that logon_type was correctly extracted as "2" (interactive logon).
# If normalisation is broken this field is often None or missing entirely.
assert failed["logon_type"] == "2"
