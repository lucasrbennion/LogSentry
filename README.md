# LogSentry

LogSentry is a rule-based prototype for the triage and prioritisation of Windows Security Event Logs. The current version parses Windows Security log text, applies explicit triage rules, assigns a priority and recommended owner, and presents the output through a lightweight React interface.

## Current scope

The current prototype focuses on a controlled set of Windows Security Event types, including successful and failed logons, privileged logons, account management activity, local group membership changes, and audit log clearing. The design prioritises explainability and operational usefulness over broad event coverage.

## Project structure

```text
backend/
  app.py
  parser.py
  rules.py
  scoring.py
  requirements.txt
  data/
    sample_windows_logs.txt
    parsed_sample_events.json
  tests/
    test_parser.py

frontend/
  package.json
  vite.config.js
  src/
    App.jsx
    main.jsx
    index.css
    components/