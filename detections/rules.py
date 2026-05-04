"""Detection rules engine.

Each rule consumes a list of synthetic event dicts and returns the subset that
matches its logic. ``run_detections`` aggregates matches into ``Alert`` objects
that the API layer persists and surfaces to the dashboard.
"""
from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Callable


@dataclass
class DetectionRule:
    id: str
    name: str
    mitre_id: str
    mitre_technique: str
    severity: str  # "critical" | "high" | "medium"
    description: str
    triage_steps: list[str]
    match: Callable[[list[dict]], list[dict]]


@dataclass
class Alert:
    id: str
    rule_id: str
    rule_name: str
    severity: str
    mitre_id: str
    mitre_technique: str
    description: str
    triage_steps: list[str]
    matched_event_count: int
    affected_accounts: list[str]
    src_ips: list[str]
    first_seen: str
    last_seen: str
    confidence: float
    matched_event_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Rule logic
# ---------------------------------------------------------------------------
def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def detect_kerberoast(events: list[dict]) -> list[dict]:
    """DET-001: >3 TGS_REQ events from one src_ip within 60s."""
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        if ev.get("event_type") == "TGS_REQ":
            by_ip[ev["src_ip"]].append(ev)

    matches: list[dict] = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e["timestamp"])
        for i, anchor in enumerate(evs):
            window = [
                e for e in evs[i:]
                if (_parse(e["timestamp"]) - _parse(anchor["timestamp"])).total_seconds() <= 60
            ]
            if len(window) > 3:
                matches.extend(window)
                break
    seen = set()
    return [e for e in matches if not (e["event_id"] in seen or seen.add(e["event_id"]))]


def detect_asrep_roast(events: list[dict]) -> list[dict]:
    """DET-002: AS_REQ events with pre_auth_enabled=False."""
    return [
        e for e in events
        if e.get("event_type") == "AS_REQ" and e.get("pre_auth_enabled") is False
    ]


def detect_password_spray(events: list[dict]) -> list[dict]:
    """DET-003: src_ip with auth failures across >5 distinct usernames and a
    failure ratio above 80% (allows some background success noise)."""
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        if ev.get("event_type") == "LDAP_BIND":
            by_ip[ev["src_ip"]].append(ev)

    matches: list[dict] = []
    for ip, evs in by_ip.items():
        failures = [e for e in evs if e.get("auth_result") == "FAILURE"]
        successes = [e for e in evs if e.get("auth_result") == "SUCCESS"]
        distinct_failed_users = {e["username"] for e in failures}
        total = len(failures) + len(successes)
        ratio = len(failures) / total if total else 0
        if len(distinct_failed_users) > 5 and ratio >= 0.8:
            matches.extend(failures)
    return matches


def detect_dcsync(events: list[dict]) -> list[dict]:
    """DET-004: replication request from a non-DC machine."""
    return [
        e for e in events
        if e.get("event_type") == "DRSUAPI_REPLICATION_REQUEST"
        and e.get("is_domain_controller") is False
    ]


def detect_acl_chain(events: list[dict]) -> list[dict]:
    """DET-005: LDAP_MODIFY adding an SPN, followed within 5min by a TGS_REQ for that SPN."""
    matches: list[dict] = []
    modifies = [
        e for e in events
        if e.get("event_type") == "LDAP_MODIFY"
        and e.get("modified_attribute") == "servicePrincipalName"
    ]
    for mod in modifies:
        spn = mod.get("new_spn_value")
        mod_ts = _parse(mod["timestamp"])
        for ev in events:
            if (
                ev.get("event_type") == "TGS_REQ"
                and ev.get("target_spn") == spn
                and 0 <= (_parse(ev["timestamp"]) - mod_ts).total_seconds() <= 300
            ):
                matches.append(mod)
                matches.append(ev)
    seen = set()
    return [e for e in matches if not (e["event_id"] in seen or seen.add(e["event_id"]))]


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------
RULES: list[DetectionRule] = [
    DetectionRule(
        id="DET-001",
        name="Kerberoasting Burst",
        mitre_id="T1558.003",
        mitre_technique="Steal or Forge Kerberos Tickets: Kerberoasting",
        severity="high",
        description="More than three TGS service-ticket requests from a single source within 60 seconds — strongly suggestive of bulk SPN harvesting.",
        triage_steps=[
            "Identify the source host and user behind the TGS_REQ burst.",
            "Check whether the requested service accounts were legitimately used by that host.",
            "Look for downstream offline-cracking tooling (Rubeus, Impacket).",
        ],
        match=detect_kerberoast,
    ),
    DetectionRule(
        id="DET-002",
        name="AS-REP Roasting",
        mitre_id="T1558.004",
        mitre_technique="Steal or Forge Kerberos Tickets: AS-REP Roasting",
        severity="high",
        description="AS_REQ activity targeting one or more accounts that have Kerberos pre-authentication disabled.",
        triage_steps=[
            "Confirm whether DONT_REQ_PREAUTH is intentionally set on each affected account.",
            "Audit recent membership changes for accounts with this flag.",
            "Force a password reset on any account that should not have pre-auth disabled.",
        ],
        match=detect_asrep_roast,
    ),
    DetectionRule(
        id="DET-003",
        name="Low-and-Slow Password Spray",
        mitre_id="T1110.003",
        mitre_technique="Brute Force: Password Spraying",
        severity="medium",
        description="A single source produced authentication failures across more than five distinct user accounts with no successful binds.",
        triage_steps=[
            "Block or rate-limit the offending source IP.",
            "Enable adaptive lockout if not already in place.",
            "Review whether any sprayed account had a recent successful login from any source.",
        ],
        match=detect_password_spray,
    ),
    DetectionRule(
        id="DET-004",
        name="DCSync from Non-Domain-Controller",
        mitre_id="T1003.006",
        mitre_technique="OS Credential Dumping: DCSync",
        severity="critical",
        description="A replication (DRSUAPI) request originated from a machine that is not a registered domain controller — extremely high-fidelity indicator of credential extraction.",
        triage_steps=[
            "Isolate the requesting host immediately.",
            "Audit which principal granted Replicating Directory Changes rights and revoke if unintended.",
            "Treat all privileged credentials as compromised pending forensic review.",
        ],
        match=detect_dcsync,
    ),
    DetectionRule(
        id="DET-005",
        name="ACL Abuse Chained to Kerberoast",
        mitre_id="T1098",
        mitre_technique="Account Manipulation",
        severity="critical",
        description="An SPN was written onto a service account and a TGS ticket for that SPN was requested shortly after — classic targeted-Kerberoast precursor.",
        triage_steps=[
            "Remove the malicious SPN from the affected account.",
            "Reset the affected account's password and rotate any dependent service credentials.",
            "Review write permissions on the account and on the OU it lives in.",
        ],
        match=detect_acl_chain,
    ),
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def _confidence(rule: DetectionRule, matched: list[dict]) -> float:
    """Cheap heuristic: more events + more affected accounts = higher confidence."""
    if not matched:
        return 0.0
    count_score = min(len(matched) / 8.0, 1.0)
    accounts = {
        m.get("target_account") or m.get("username")
        for m in matched
        if m.get("target_account") or m.get("username")
    }
    breadth_score = min(len(accounts) / 6.0, 1.0)
    severity_floor = {"critical": 0.85, "high": 0.7, "medium": 0.55}[rule.severity]
    return round(min(1.0, severity_floor + 0.15 * (count_score + breadth_score) / 2), 2)


def run_detections(events: list[dict]) -> list[Alert]:
    """Run every rule against ``events`` and return one Alert per fired rule."""
    alerts: list[Alert] = []
    for rule in RULES:
        matched = rule.match(events)
        if not matched:
            continue
        timestamps = sorted(m["timestamp"] for m in matched)
        accounts = sorted({
            m.get("target_account") or m.get("username")
            for m in matched
            if m.get("target_account") or m.get("username")
        })
        ips = sorted({m.get("src_ip") for m in matched if m.get("src_ip")})
        alerts.append(Alert(
            id=str(uuid.uuid4()),
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            mitre_id=rule.mitre_id,
            mitre_technique=rule.mitre_technique,
            description=rule.description,
            triage_steps=list(rule.triage_steps),
            matched_event_count=len(matched),
            affected_accounts=accounts,
            src_ips=ips,
            first_seen=timestamps[0],
            last_seen=timestamps[-1],
            confidence=_confidence(rule, matched),
            matched_event_ids=[m["event_id"] for m in matched],
        ))
    return alerts
