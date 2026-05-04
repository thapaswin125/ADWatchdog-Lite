# ADWatchdog Lite

**A detection-engineering workbench for Active Directory attacks — without the AD.**
ADWatchdog Lite simulates the kinds of attacks adversaries run against enterprise
identity systems (Kerberoasting, DCSync, password spray, ACL abuse, AS-REP roasting),
runs real detection logic against the resulting event stream, and uses Claude to
produce a triage runbook a junior SOC analyst can act on. There is no real
domain controller, no virtual machines, no Samba — the whole lab runs from a
single `make dev` command and is meant to be a fast, demonstrable showcase of
detection-engineering thinking, not a production SIEM.

---

## Architecture

```
 ┌──────────────────┐    ┌────────────────────┐    ┌────────────┐
 │ Synthetic Log    │ ─► │ Detection Engine   │ ─► │  SQLite    │
 │ Generator        │    │ (5 rules, MITRE-   │    │ (lab.db)   │
 │ (5 attacks +     │    │  mapped, conf-     │    └─────┬──────┘
 │  baseline noise) │    │  scored)           │          │
 └──────────────────┘    └────────────────────┘          ▼
                                                  ┌────────────┐
                                                  │  FastAPI   │
                                                  └─────┬──────┘
                                                        │
                              ┌─────────────────────────┴────────────────┐
                              ▼                                          ▼
                    ┌────────────────────┐                   ┌─────────────────────┐
                    │  React Dashboard   │                   │ Runbook Generator   │
                    │ (Vite + Tailwind)  │ ◄──── runbook ─── │ → Claude Sonnet API │
                    └────────────────────┘                   └─────────────────────┘
```

---

## Setup

```bash
pip install -r requirements.txt
cd dashboard && npm install && cd ..
make dev          # API on :8000, dashboard on :5173
```

Optional: drop your Anthropic key in `.env` (or export `ANTHROPIC_API_KEY`) to
enable AI-generated runbooks. Without a key, the runbook endpoint returns a
clean offline template so the demo still works end-to-end.

---

## Demo walkthrough — A1 Kerberoasting

1. Open `http://localhost:5173`.
2. In the **Attack Launcher** (left), find `A1 — Kerberoasting`. Leave it on
   **Noisy** mode and click **Run Simulation**.
3. The simulator produces ~6 `TGS_REQ` events from a single internal IP
   targeting six different service accounts, mixed in with ~50 baseline
   logins/LDAP events. The detection engine runs all five rules against the
   stream; **DET-001 — Kerberoasting Burst** fires.
4. The new alert appears in the **Live Alert Feed** (center) within a second,
   color-coded by severity, with a confidence bar.
5. Click the alert → the **Triage Drawer** (right) opens, showing the matched
   event timeline in a monospace log view.
6. Click **Generate Runbook**. Claude produces a markdown runbook covering
   Incident Summary, IOCs, kill chain narrative, containment steps, evidence
   to collect, and a false-positive check. **Download .md** saves it locally;
   the same file is also persisted to `runbooks/output/`.
7. The top stats bar updates: total alerts, criticals, MITRE techniques fired,
   runbooks generated.

Repeat with A2–A5 to drive coverage to **5 / 5 techniques detected**.

---

## Detection coverage

| Rule    | Name                                | MITRE ID    | Severity | Logic summary                                                              |
| ------- | ----------------------------------- | ----------- | -------- | -------------------------------------------------------------------------- |
| DET-001 | Kerberoasting Burst                 | T1558.003   | high     | More than 3 `TGS_REQ` from one source IP within a 60-second window.        |
| DET-002 | AS-REP Roasting                     | T1558.004   | high     | Any `AS_REQ` against an account where pre-authentication is disabled.      |
| DET-003 | Low-and-Slow Password Spray         | T1110.003   | medium   | One source IP, failures across >5 distinct users, >80% failure ratio.      |
| DET-004 | DCSync from Non-Domain-Controller   | T1003.006   | critical | Replication request originating from a host that is not a registered DC.  |
| DET-005 | ACL Abuse Chained to Kerberoast     | T1098       | critical | SPN written to an account, then a TGS for that SPN within 5 minutes.       |

Each rule emits an alert with a confidence score, the affected accounts and
source IPs, the matched event IDs, and a set of curated triage steps.

---

## Make targets

| Command              | Effect                                                           |
| -------------------- | ---------------------------------------------------------------- |
| `make install`       | Install Python and Node dependencies.                            |
| `make dev`           | Run the API (`:8000`) and dashboard (`:5173`) together.          |
| `make api`           | Run only the FastAPI backend.                                    |
| `make dashboard`     | Run only the Vite dev server.                                    |
| `make simulate A=A3` | Fire a scenario from the CLI without the UI.                     |
| `make reset`         | Wipe `lab.db` and clear the `runbooks/output/` directory.        |

---

## Project layout

```
adwatchdog-lite/
├── simulator/            # synthetic event generators, one per attack
│   ├── generator.py
│   └── cli.py
├── detections/           # rule definitions + run_detections()
│   └── rules.py
├── runbooks/             # AI runbook generator + saved outputs
│   ├── generator.py
│   └── output/
├── api/                  # FastAPI app + sqlite layer
│   ├── main.py
│   └── db.py
├── dashboard/            # React + Vite + Tailwind UI
│   ├── src/components/
│   └── src/lib/
├── requirements.txt
├── Makefile
└── README.md
```

---

## Tech stack

- **Backend:** Python 3.12, FastAPI, uvicorn, sqlite3, anthropic SDK
- **Frontend:** React 18, Vite, Tailwind CSS, marked
- **Model:** `claude-sonnet-4-20250514` (configurable in `runbooks/generator.py`)
