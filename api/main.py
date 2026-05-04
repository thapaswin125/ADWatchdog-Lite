"""FastAPI backend for ADWatchdog Lite."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from detections import run_detections
from runbooks import generate_runbook, save_runbook as write_runbook_file
from simulator import SCENARIOS, run_scenario

from . import db


db.init_db()

app = FastAPI(title="ADWatchdog Lite API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class SimulateRequest(BaseModel):
    scenario_id: str = Field(..., description="One of A1..A5")
    stealth: int = Field(0, ge=0, le=1, description="0=noisy, 1=stealthy")


class ScenarioOut(BaseModel):
    id: str
    name: str
    mitre_id: str
    severity: str
    description: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/api/scenarios", response_model=list[ScenarioOut])
def list_scenarios() -> list[ScenarioOut]:
    return [
        ScenarioOut(
            id=s.id, name=s.name, mitre_id=s.mitre_id,
            severity=s.severity, description=s.description,
        )
        for s in SCENARIOS.values()
    ]


@app.post("/api/simulate")
def simulate(req: SimulateRequest) -> dict:
    if req.scenario_id not in SCENARIOS:
        raise HTTPException(404, f"Unknown scenario {req.scenario_id}")

    events = run_scenario(req.scenario_id, stealth=req.stealth)
    alerts = run_detections(events)

    event_to_alert: dict[str, str] = {}
    for alert in alerts:
        for eid in alert.matched_event_ids:
            event_to_alert[eid] = alert.id

    for alert in alerts:
        db.insert_alert(alert.to_dict())
    db.insert_events(events, event_to_alert)

    return {
        "scenario_id": req.scenario_id,
        "events_generated": len(events),
        "alerts": [a.to_dict() for a in alerts],
    }


@app.get("/api/alerts")
def get_alerts() -> list[dict]:
    return db.list_alerts()


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict:
    alert = db.get_alert(alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    return alert


@app.post("/api/alerts/{alert_id}/runbook")
def generate_alert_runbook(alert_id: str) -> dict:
    alert = db.get_alert(alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")

    # Re-hydrate as a lightweight object with attribute access.
    class _AlertView:
        pass
    view = _AlertView()
    for key in (
        "id", "rule_id", "rule_name", "severity", "mitre_id", "mitre_technique",
        "description", "triage_steps", "matched_event_count",
        "affected_accounts", "src_ips", "first_seen", "last_seen", "confidence",
    ):
        setattr(view, key, alert[key])

    markdown = generate_runbook(view, alert.get("events", []))
    db.save_runbook(alert_id, markdown)
    path = write_runbook_file(alert_id, markdown)
    return {"alert_id": alert_id, "runbook_md": markdown, "saved_to": str(path)}


@app.get("/api/stats")
def get_stats() -> dict:
    return db.stats()


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}
