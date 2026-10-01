# REST API Reference

All endpoints are local-development oriented by default.

- `POST /api/flows` — validate, detect, score and persist a flow.
- `GET /api/flows` — list flows.
- `GET /api/flows/{flow_id}` — retrieve a flow.
- `GET /api/alerts` — filter/list alerts.
- `GET /api/alerts/{alert_id}` — retrieve alert plus notes.
- `PUT /api/alerts/{alert_id}/status` — update incident status.
- `POST /api/alerts/{alert_id}/notes` — add analyst note.
- `GET /api/dashboard/stats` — dashboard KPIs.
- `GET /api/dashboard/traffic` — traffic/risk time series.
- `GET /api/dashboard/alerts` — severity, types, protocol, port and source summaries.
- `GET /api/rules` — list configured rules.
- `PUT /api/rules/{rule_id}` — update threshold and enabled state.
