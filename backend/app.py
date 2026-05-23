from flask import Flask, jsonify, request
from parser import normalize_events
from rules import evaluate_event
from scoring import score_event, summarise_results

app = Flask(__name__)

@app.get("/health")
def health():
    return jsonify({"status": "ok", "app": "LogSentry"})

@app.post("/triage")
def triage():
    payload = request.get_json(silent=True) or {}
    raw_events = payload.get("events", [])
    normalized = normalize_events(raw_events)

    results = []
    for event in normalized:
        rule_hits = evaluate_event(event)
        triaged = score_event(event, rule_hits)
        results.append(triaged)

    summary = summarise_results(results)
    return jsonify({"summary": summary, "results": results})

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
