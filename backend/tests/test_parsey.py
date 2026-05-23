from pathlib import Path
from parser import parse_file

sample = Path(__file__).resolve().parents[1] / "data" / "sample_windows_logs.txt"
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

print("All parsey.py tests passed.")
