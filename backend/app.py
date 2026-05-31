# app.py — the main entry point for the LogSentry Flask API.
# It exposes two POST endpoints: one that accepts raw JSON events and one that
# accepts a file path pointing to a Windows event log text file.
# Both endpoints run the events through the same normalise → rule-match → score pipeline.

from pathlib import Path

from flask import Flask, jsonify, request

from parser import normalize_events, parse_file
from rules import evaluate_event
from scoring import score_event, summarise_results

app = Flask(__name__)


def run_triage(events: list[dict]) -> dict:
    """Run every event through the rule engine and scorer, then return a summary.

    For each event:
      1. evaluate_event  — checks which security rules fire
      2. score_event     — assigns a priority level and recommended owner
    After all events are processed, summarise_results produces aggregate counts.
    """
    results = []

    for event in events:
        rule_hits = evaluate_event(event)       # which rules matched this event
        triaged = score_event(event, rule_hits)  # turn rule hits into a priority + owner
        results.append(triaged)

    summary = summarise_results(results)  # aggregate stats across all events
    return {"summary": summary, "results": results}


@app.get("/health")
def health():
    # Simple liveness check so load-balancers / monitoring tools can confirm the app is running.
    return jsonify({"status": "ok", "app": "LogSentry"})


@app.post("/triage")
def triage():
    """Accept a list of pre-parsed event dicts and return triage results.

    Expected request body:
        { "events": [ { ...event dict... }, ... ] }

    The events are first normalised (field names are standardised) and then
    fed through the rule engine and scorer.
    """
    payload = request.get_json(silent=True) or {}
    raw_events = payload.get("events", [])

    if not raw_events:
        return jsonify({"error": "No events provided in payload"}), 400

    # Normalise flattens provider-specific field names into a consistent schema.
    normalized = normalize_events(raw_events)
    output = run_triage(normalized)
    return jsonify(output)


@app.post("/triage-file")
def triage_file():
    """Accept a path to a raw Windows event log text file and return triage results.

    Expected request body:
        { "file_path": "C:\\\\path\\\\to\\\\sample_windows_logs.txt" }

    The file is parsed from the raw Windows format, normalised, then triaged.
    Use this endpoint when you have a raw log export rather than pre-parsed JSON.
    """
    payload = request.get_json(silent=True) or {}
    file_path = payload.get("file_path")

    if not file_path:
        return jsonify({"error": "file_path is required"}), 400

    path = Path(file_path)
    if not path.exists():
        return jsonify({"error": f"File not found: {file_path}"}), 404

    # parse_file handles reading the file and splitting it into individual event records.
    parsed_events = parse_file(path)
    output = run_triage(parsed_events)
    return jsonify(output)


if __name__ == "__main__":
    # Run the development server on localhost only.
    # Do not expose debug=True on a production host.
    app.run(debug=True, host="127.0.0.1", port=5000)
