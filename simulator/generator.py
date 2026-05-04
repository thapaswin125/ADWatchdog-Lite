"""Synthetic Active Directory event log generator.

Produces realistic-looking JSON event records for five attack scenarios plus a
baseline of normal activity. No real domain controller, agents, or network
traffic involved — this is purely structured data for detection-engine demos.
"""
from __future__ import annotations

import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable


SERVICE_ACCOUNTS = [
    "svc_sql", "svc_iis", "svc_backup", "svc_exchange", "svc_sharepoint",
    "svc_jenkins", "svc_vmware", "svc_monitor", "svc_reports", "svc_archive",
]

USER_ACCOUNTS = [
    "alice.lin", "bob.tanaka", "carol.diaz", "david.osei", "eva.kowalski",
    "frank.weber", "grace.huang", "henry.patel", "ivy.rossi", "jack.muller",
    "kira.smith", "leo.fischer", "mia.nakamura", "noah.adams", "olivia.singh",
    "paul.romero", "quinn.zhao", "ruth.kovacs", "sam.dubois", "tara.popov",
    "uri.lambert", "vera.olsen", "will.hassan", "xara.ito", "yuri.becker",
]

INTERNAL_IPS = [
    "10.10.20.15", "10.10.20.42", "10.10.21.8", "10.10.22.91",
    "10.10.30.11", "10.10.30.55",
]

DC_IPS = ["10.10.10.5", "10.10.10.6"]
HOSTNAMES = ["WS-FIN-01", "WS-ENG-04", "WS-HR-12", "LAPTOP-DEV-22", "WS-OPS-09"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(ts: datetime) -> str:
    return ts.isoformat(timespec="seconds")


def _make_event(event_type: str, ts: datetime, **fields) -> dict:
    base = {
        "event_id": str(uuid.uuid4()),
        "timestamp": _iso(ts),
        "event_type": event_type,
    }
    base.update(fields)
    return base


def _stealth_delay(stealth: int, fast: float, slow: float) -> float:
    """Linearly interpolate between fast (stealth=0) and slow (stealth=1)."""
    stealth = max(0, min(1, stealth))
    return fast + (slow - fast) * stealth


# ---------------------------------------------------------------------------
# A1 — Kerberoasting
# ---------------------------------------------------------------------------
def generate_kerberoast(stealth: int = 0) -> list[dict]:
    """Burst of TGS_REQ events targeting many service accounts from one IP."""
    events: list[dict] = []
    src_ip = random.choice(INTERNAL_IPS)
    actor = random.choice(USER_ACCOUNTS)
    targets = random.sample(SERVICE_ACCOUNTS, k=6)
    base = _now()
    gap = _stealth_delay(stealth, fast=2.0, slow=12.0)

    for i, svc in enumerate(targets):
        ts = base + timedelta(seconds=i * gap)
        enc = "RC4_HMAC_MD5" if i % 3 != 0 else "AES256_CTS_HMAC_SHA1_96"
        events.append(_make_event(
            "TGS_REQ",
            ts,
            src_ip=src_ip,
            username=actor,
            target_spn=f"MSSQLSvc/{svc}.corp.local:1433",
            target_account=svc,
            ticket_encryption_type=enc,
            request_status="SUCCESS",
        ))
    return events


# ---------------------------------------------------------------------------
# A2 — AS-REP Roasting
# ---------------------------------------------------------------------------
def generate_asrep_roast(stealth: int = 0) -> list[dict]:
    """AS-REQ events for accounts with Kerberos pre-auth disabled."""
    events: list[dict] = []
    src_ip = random.choice(INTERNAL_IPS)
    targets = random.sample(USER_ACCOUNTS, k=4)
    base = _now()
    gap = _stealth_delay(stealth, fast=3.0, slow=20.0)

    for i, user in enumerate(targets):
        ts = base + timedelta(seconds=i * gap)
        events.append(_make_event(
            "AS_REQ",
            ts,
            src_ip=src_ip,
            username=user,
            pre_auth_enabled=False,
            response_hash_stub=f"$krb5asrep$23${user}@CORP.LOCAL:" + uuid.uuid4().hex[:24],
            request_status="SUCCESS",
        ))
    return events


# ---------------------------------------------------------------------------
# A3 — Password Spray
# ---------------------------------------------------------------------------
def generate_password_spray(stealth: int = 0) -> list[dict]:
    """One failed bind per account, spread across many accounts, single IP."""
    events: list[dict] = []
    src_ip = random.choice(INTERNAL_IPS)
    targets = random.sample(USER_ACCOUNTS, k=22)
    base = _now()
    gap = _stealth_delay(stealth, fast=10.0, slow=30.0)

    for i, user in enumerate(targets):
        ts = base + timedelta(seconds=i * gap)
        events.append(_make_event(
            "LDAP_BIND",
            ts,
            src_ip=src_ip,
            username=user,
            auth_result="FAILURE",
            failure_reason="WRONG_PASSWORD",
        ))
    return events


# ---------------------------------------------------------------------------
# A4 — DCSync
# ---------------------------------------------------------------------------
def generate_dcsync(stealth: int = 0) -> list[dict]:
    """Replication request from a non-DC machine."""
    events: list[dict] = []
    src_ip = random.choice(INTERNAL_IPS)
    machine = random.choice(HOSTNAMES)
    actor = random.choice(USER_ACCOUNTS)
    base = _now()
    gap = _stealth_delay(stealth, fast=1.0, slow=5.0)

    for i in range(2):
        ts = base + timedelta(seconds=i * gap)
        events.append(_make_event(
            "DRSUAPI_REPLICATION_REQUEST",
            ts,
            src_ip=src_ip,
            username=actor,
            requesting_machine=machine,
            is_domain_controller=False,
            replicated_attributes=["unicodePwd", "ntPwdHistory", "supplementalCredentials"],
            target_object="CN=Users,DC=corp,DC=local",
        ))
    return events


# ---------------------------------------------------------------------------
# A5 — ACL Abuse → Kerberoast Chain
# ---------------------------------------------------------------------------
def generate_acl_chain(stealth: int = 0) -> list[dict]:
    """LDAP write adding an SPN, immediately followed by a TGS_REQ for it."""
    events: list[dict] = []
    src_ip = random.choice(INTERNAL_IPS)
    actor = random.choice(USER_ACCOUNTS)
    target = random.choice(SERVICE_ACCOUNTS)
    new_spn = f"HTTP/{target}.corp.local"
    base = _now()
    gap = _stealth_delay(stealth, fast=1.0, slow=4.0)

    events.append(_make_event(
        "LDAP_MODIFY",
        base,
        src_ip=src_ip,
        actor_username=actor,
        username=actor,
        target_account=target,
        modified_attribute="servicePrincipalName",
        new_spn_value=new_spn,
        operation="ADD",
    ))
    events.append(_make_event(
        "TGS_REQ",
        base + timedelta(seconds=gap),
        src_ip=src_ip,
        username=actor,
        target_spn=new_spn,
        target_account=target,
        ticket_encryption_type="RC4_HMAC_MD5",
        request_status="SUCCESS",
    ))
    return events


# ---------------------------------------------------------------------------
# Baseline noise
# ---------------------------------------------------------------------------
def generate_baseline(count: int = 50) -> list[dict]:
    """Normal login + LDAP read activity to mix in alongside attack traffic."""
    events: list[dict] = []
    base = _now() - timedelta(minutes=10)

    for i in range(count):
        ts = base + timedelta(seconds=i * random.uniform(5, 25))
        kind = random.choices(
            ["LOGIN_SUCCESS", "LDAP_BIND", "LDAP_SEARCH"],
            weights=[5, 3, 4],
        )[0]
        user = random.choice(USER_ACCOUNTS)
        ip = random.choice(INTERNAL_IPS)

        if kind == "LOGIN_SUCCESS":
            events.append(_make_event(
                "LOGIN_SUCCESS", ts,
                src_ip=ip, username=user,
                workstation=random.choice(HOSTNAMES),
                logon_type=random.choice([2, 3, 10]),
            ))
        elif kind == "LDAP_BIND":
            events.append(_make_event(
                "LDAP_BIND", ts,
                src_ip=ip, username=user,
                auth_result="SUCCESS",
            ))
        else:
            events.append(_make_event(
                "LDAP_SEARCH", ts,
                src_ip=ip, username=user,
                base_dn="DC=corp,DC=local",
                filter="(objectClass=user)",
            ))
    return events


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------
@dataclass
class Scenario:
    id: str
    name: str
    mitre_id: str
    severity: str
    description: str
    generator: Callable[[int], list[dict]]


SCENARIOS: dict[str, Scenario] = {
    "A1": Scenario(
        id="A1",
        name="Kerberoasting",
        mitre_id="T1558.003",
        severity="high",
        description="Adversary requests TGS tickets for service accounts to crack offline.",
        generator=generate_kerberoast,
    ),
    "A2": Scenario(
        id="A2",
        name="AS-REP Roasting",
        mitre_id="T1558.004",
        severity="high",
        description="Adversary harvests AS-REP responses for accounts with pre-auth disabled.",
        generator=generate_asrep_roast,
    ),
    "A3": Scenario(
        id="A3",
        name="Password Spray",
        mitre_id="T1110.003",
        severity="medium",
        description="Low-and-slow auth attempts against many accounts from one source.",
        generator=generate_password_spray,
    ),
    "A4": Scenario(
        id="A4",
        name="DCSync",
        mitre_id="T1003.006",
        severity="critical",
        description="Non-DC host requests directory replication to extract credential material.",
        generator=generate_dcsync,
    ),
    "A5": Scenario(
        id="A5",
        name="ACL Abuse → Kerberoast",
        mitre_id="T1098",
        severity="critical",
        description="Adversary writes an SPN onto a service account then Kerberoasts it.",
        generator=generate_acl_chain,
    ),
}


def run_scenario(scenario_id: str, stealth: int = 0, with_baseline: bool = True) -> list[dict]:
    """Run a scenario and optionally interleave baseline noise. Returns sorted events."""
    if scenario_id not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario_id}")
    attack = SCENARIOS[scenario_id].generator(stealth)
    events = attack + (generate_baseline() if with_baseline else [])
    events.sort(key=lambda e: e["timestamp"])
    return events
