from pathlib import Path
import sys

#These two lines make the backend directory importable so the test can find parser.py
BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from parser import parse_file
from pathlib import Path

sample = Path(__file__).resolve().parents[1] / "data" / "sample_windows_logs.txt"
results = parse_file(sample)

failed = next(r for r in results if r["event_id"] == 4625)

print(failed)
assert failed["logon_type"] == "2"