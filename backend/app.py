# app.py — the main entry point for the LogSentry Flask API.
# It exposes:
#   1. /triage            — triage event dicts passed directly in the request body
#   2. /triage-file       — triage a raw Windows event-log text file by path
#   3. /triage-json-file  — triage a JSON file containing a generated event dataset
#   4. /generated-files   — list compatible .txt/.json datasets from backend/data/generated
#
# The generated-files route exists to support a cleaner UI workflow:
# the frontend no longer asks the user to type long Windows file paths manually.
# Instead, the app loads the default generated-data folder and lets the user
# choose a compatible file from inside the interface.

from __future__ import annotations

import json
from pathlib import Path

from flask import Flask, jsonify, request

from parser import normalize_events, parse_file
from rules import evaluate_event
from scoring import score_event, summarise_results

app = Flask(__name__)

# The default folder that the frontend should "point to" when loading datasets.
# Keeping this on the backend avoids fragile hard-coded paths in the browser UI.
GENERATED_DATA_DIR = Path(__file__).resolve().parent / "data" / "generated"


def run_triage(events: list[dict]) -> dict:
    """Run every event through the rule engine and scorer, then return a summary."""
    results = []

    for event in events:
        rule_hits = evaluate_event(event)
        triaged = score_event(event, rule_hits)
        results.append(triaged)

    summary = summarise_results(results)
    return {"summary": summary, "results": results}


def load_events_from_json_file(path: Path) -> list[dict]:
    """Load an event list from a JSON file.

    Supported file shapes:
      1. A top-level list:
           [ {...}, {...} ]

      2. A dict with an "events" property:
           { "events": [ {...}, {...} ] }

    The returned list is still passed through normalize_events so the rest of the
    backend can treat it exactly like any other input source.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON file: {exc}") from exc

    if isinstance(payload, list):
        events = payload
    elif isinstance(payload, dict):
        events = payload.get("events", [])
    else:
        raise ValueError("JSON file must contain either a list of events or an object with an 'events' key.")

    if not isinstance(events, list):
        raise ValueError("'events' must be a list.")
    if not events:
        raise ValueError("No events found in JSON file.")

    return events


def list_generated_dataset_files() -> list[dict]:
    """Return compatible dataset files from the generated-data folder.

    Only .txt and .json files are returned because those are the two dataset
    shapes the current application can triage through the UI.
    """
    if not GENERATED_DATA_DIR.exists():
        return []

    files = []
    for path in sorted(GENERATED_DATA_DIR.iterdir()):
        if not path.is_file():
            continue

        suffix = path.suffix.lower()
        if suffix not in {".txt", ".json"}:
            continue

        kind = "json_events" if suffix == ".json" else "raw_text"
        kind_label = "Generated JSON event dataset" if kind == "json_events" else "Raw Windows text log"

        files.append(
            {
                "name": path.name,
                "path": str(path),
                "kind": kind,
                "kind_label": kind_label,
            }
        )

    return files


@app.get("/health")
def health():
    """Simple liveness check used by the frontend and local debugging."""
    return jsonify({"status": "ok", "app": "LogSentry"})


@app.get("/generated-files")
def generated_files():
    """Return the generated-data folder path and the compatible files inside it.

    The frontend uses this route to populate the in-app "Load logs" picker so that
    the user can choose a .txt or .json dataset without typing a path manually.
    """
    return jsonify(
        {
            "folder": str(GENERATED_DATA_DIR),
            "files": list_generated_dataset_files(),
        }
    )


@app.post("/triage")
def triage():
    """Accept a list of event dicts directly in the request body and return triage results."""
    payload = request.get_json(silent=True) or {}
    raw_events = payload.get("events", [])

    if not raw_events:
        return jsonify({"error": "No events provided in payload"}), 400

    normalized = normalize_events(raw_events)
    output = run_triage(normalized)
    return jsonify(output)


@app.post("/triage-file")
def triage_file():
    """Accept a path to a raw Windows event-log text file and return triage results."""
    payload = request.get_json(silent=True) or {}
    file_path = payload.get("file_path")

    if not file_path:
        return jsonify({"error": "file_path is required"}), 400

    path = Path(file_path)
    if not path.exists():
        return jsonify({"error": f"File not found: {file_path}"}), 404

    parsed_events = parse_file(path)
    output = run_triage(parsed_events)
    return jsonify(output)


@app.post("/triage-json-file")
def triage_json_file():
    """Accept a path to a JSON file containing a large event dataset and return triage results."""
    payload = request.get_json(silent=True) or {}
    file_path = payload.get("file_path")

    if not file_path:
        return jsonify({"error": "file_path is required"}), 400

    path = Path(file_path)
    if not path.exists():
        return jsonify({"error": f"File not found: {file_path}"}), 404

    try:
        raw_events = load_events_from_json_file(path)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    normalized = normalize_events(raw_events)
    output = run_triage(normalized)
    return jsonify(output)


if __name__ == "__main__":
    # Development server only.
    app.run(debug=True, host="127.0.0.1", port=5000)