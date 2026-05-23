# LogSentry

LogSentry is a rule-based prototype for the triage and prioritisation of Windows Security Event Logs.

## Project structure

```text
backend/
  app.py
  parser.py
  rules.py
  scoring.py
  config/
  data/
  outputs/

frontend/
  src/
    App.jsx
    components/
```

## Backend quick start

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

## Test the backend

Use the sample file:

```bash
curl -X POST http://127.0.0.1:5000/triage ^
  -H "Content-Type: application/json" ^
  --data @data/sample_events.json
```

## Notes

- The backend is the main analytical component.
- The frontend is a lightweight React shell for triage visualisation.
- Claude Code can support development, but it is not part of the artefact itself.
