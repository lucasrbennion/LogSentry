from pathlib import Path

# This is the main Flask application for LogSentry.
# The code class used to create the web application, define routes, and handle incoming requests.

from flask import Flask, jsonify, request 

from parser import normalize_event, parse_file
from rules import evaluate_event
from scoring import score_event, summarise_results

app = Flask(__name__)


def run_triage(events: list[dict]) -> dict:
    results = []

    for event in events:
        rule_hits = evaluate_event(event)
        triaged = score_event(event, rule_hits)
        results.append(triaged)

    summary = summarise_results(results)
    return {"summary": summary, "results": results}


@app.get("/health")
def health():
    return jsonify({"status": "ok", "app": "LogSentry"})


@app.post("/triage")
def triage():
    """
    Existing JSON-based endpoint.
    Expects payload like:
    {
        "events": [...]
    }
    """
    payload = request.get_json(silent=True) or {}
    raw_events = payload.get("events", [])

    if not raw_events:
        return jsonify({"error": "No events provided in payload"}), 400

    normalized = normalize_event(raw_events)
    output = run_triage(normalized)
    return jsonify(output)


@app.post("/triage-file")
def triage_file():
    """
    File-based endpoint for raw Windows log text.
    Expects payload like:
    {
        "file_path": "C:\\\\PythonProjects\\\\LogSentry\\\\backend\\\\data\\\\sample_windows_logs.txt"
    }
    """
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


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)