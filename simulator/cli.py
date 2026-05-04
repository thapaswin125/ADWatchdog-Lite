"""CLI helper: ``python -m simulator.cli A1`` runs a scenario and prints alerts."""
from __future__ import annotations

import json
import sys

from detections import run_detections

from .generator import SCENARIOS, run_scenario


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] in {"-h", "--help"}:
        print("usage: python -m simulator.cli <A1|A2|A3|A4|A5> [stealth=0]")
        return 0
    sid = argv[1]
    if sid not in SCENARIOS:
        print(f"Unknown scenario: {sid}. Choose from: {', '.join(SCENARIOS)}")
        return 2
    stealth = int(argv[2]) if len(argv) > 2 else 0

    events = run_scenario(sid, stealth=stealth)
    alerts = run_detections(events)

    print(f"Scenario {sid} → {len(events)} events, {len(alerts)} alert(s)\n")
    for a in alerts:
        print(f"  {a.rule_id} [{a.severity.upper()}] {a.rule_name}")
        print(f"    MITRE: {a.mitre_id} | confidence: {a.confidence:.2f}")
        print(f"    {a.matched_event_count} events, {len(a.affected_accounts)} account(s)")
        print(f"    accounts: {', '.join(a.affected_accounts)}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
