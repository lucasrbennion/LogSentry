# app.py — the main entry point for the LogSentry Flask API.
# It exposes:
#   1. /triage           — triage event dicts passed directly in the request body
#   2. /triage-file      — triage a raw Windows event-log text file by path
#   3. /triage-json-file — triage a JSON file containing a large generated event dataset
#
# The JSON-file route is useful for scale testing because it avoids having to paste or
# upload thousands of events through the frontend.  The frontend can simply provide a
# file path, and the backend loads the dataset locally.

from __future__ import annotations

import json
from pathlib import Path

from flask import Flask, jsonify, request

from parser import normalize_events, parse_file
from rules import evaluate_event
from scoring import score_event, summarise_results

app = Flask(__name__)


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


@app.get("/health")
def health():
    """Simple liveness check used by the frontend and local debugging."""
    return jsonify({"status": "ok", "app": "LogSentry"})


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
    """Accept a path to a JSON file containing a large event dataset and return triage results.

    This route is intended for scale testing with generated datasets such as:
      backend/data/generated/generated_events_2000.json
    """
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