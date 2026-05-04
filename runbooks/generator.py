"""AI-generated SOC triage runbooks.

Constructs a structured prompt from an alert + its matched events and asks
Claude to write a markdown runbook. Falls back to a deterministic template if
no API key is configured so the demo still works offline.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

SYSTEM_PROMPT = (
    "You are a senior SOC analyst writing a concise triage runbook for a "
    "junior analyst. Be specific, practical, and actionable."
)

MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 1000


def _summarize_events(matched_events: list[dict], limit: int = 12) -> str:
    """Render matched events as a compact text timeline (not raw JSON)."""
    if not matched_events:
        return "(no events available)"
    lines: list[str] = []
    for ev in matched_events[:limit]:
        ts = ev.get("timestamp", "?")
        et = ev.get("event_type", "?")
        ip = ev.get("src_ip", "?")
        user = ev.get("username") or ev.get("actor_username") or "?"
        target = (
            ev.get("target_spn")
            or ev.get("target_account")
            or ev.get("new_spn_value")
            or ev.get("requesting_machine")
            or ""
        )
        extra = []
        if "auth_result" in ev:
            extra.append(f"result={ev['auth_result']}")
        if "ticket_encryption_type" in ev:
            extra.append(f"enc={ev['ticket_encryption_type']}")
        if "modified_attribute" in ev:
            extra.append(f"attr={ev['modified_attribute']}")
        suffix = (" " + " ".join(extra)) if extra else ""
        lines.append(f"- {ts}  {et}  src={ip}  user={user}  target={target}{suffix}")
    if len(matched_events) > limit:
        lines.append(f"- ... and {len(matched_events) - limit} more events")
    return "\n".join(lines)


def build_prompt(alert: Any, matched_events: list[dict]) -> str:
    """Assemble the user-message body for Claude."""
    accounts = ", ".join(alert.affected_accounts) or "(none identified)"
    ips = ", ".join(alert.src_ips) or "(none identified)"
    timeline = _summarize_events(matched_events)
    return f"""Write a markdown triage runbook for the alert below.

## Alert
- Rule: {alert.rule_id} — {alert.rule_name}
- Severity: {alert.severity.upper()}
- MITRE: {alert.mitre_id} ({alert.mitre_technique})
- Confidence: {alert.confidence:.2f}
- First seen: {alert.first_seen}
- Last seen: {alert.last_seen}
- Matched events: {alert.matched_event_count}
- Affected accounts: {accounts}
- Source IPs: {ips}

## Detection rationale
{alert.description}

## Timeline of matched events
{timeline}

## Required sections (use these exact H2 headers)
## Incident Summary
## IOCs
## What Likely Happened
## Immediate Containment Steps
## Evidence to Collect
## False Positive Check

Keep each section short and actionable. Use bullet points where natural. Do
not invent IPs or accounts that are not listed above."""


def _fallback_runbook(alert: Any, matched_events: list[dict]) -> str:
    """Deterministic offline template for when ANTHROPIC_API_KEY is unset."""
    accounts = ", ".join(alert.affected_accounts) or "(none identified)"
    ips = ", ".join(alert.src_ips) or "(none identified)"
    triage = "\n".join(f"- {step}" for step in alert.triage_steps)
    timeline = _summarize_events(matched_events, limit=8)
    return f"""# {alert.rule_id} — {alert.rule_name}

## Incident Summary
A **{alert.severity.upper()}** detection fired against {alert.matched_event_count}
event(s) between {alert.first_seen} and {alert.last_seen}. Mapped to
**{alert.mitre_id} ({alert.mitre_technique})** with confidence
{alert.confidence:.2f}.

## IOCs
- Source IPs: {ips}
- Affected accounts: {accounts}

## What Likely Happened
{alert.description}

## Immediate Containment Steps
{triage}

## Evidence to Collect
- Full event timeline for the source IP(s) above (±30 minutes).
- Endpoint process telemetry on the originating host.
- Any concurrent successful authentications from the same IP.

## False Positive Check
- Was a sanctioned admin or vulnerability scan responsible for this traffic?
- Was the source host recently re-imaged or repurposed?

## Timeline (matched events)
```
{timeline}
```

_(Offline template — set `ANTHROPIC_API_KEY` to get an AI-generated runbook.)_
"""


def generate_runbook(alert: Any, matched_events: list[dict]) -> str:
    """Return a markdown runbook for ``alert``. Uses Claude when configured."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return _fallback_runbook(alert, matched_events)

    try:
        import anthropic  # noqa: WPS433  (deferred import keeps offline path light)
    except ImportError:
        return _fallback_runbook(alert, matched_events)

    client = anthropic.Anthropic(api_key=api_key)
    prompt = build_prompt(alert, matched_events)
    try:
        msg = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        chunks = [b.text for b in msg.content if getattr(b, "type", "") == "text"]
        body = "\n".join(chunks).strip()
        if not body:
            return _fallback_runbook(alert, matched_events)
        header = f"# {alert.rule_id} — {alert.rule_name}\n\n"
        return body if body.lstrip().startswith("#") else header + body
    except Exception as exc:  # network error, auth error, etc.
        return _fallback_runbook(alert, matched_events) + f"\n\n_(API call failed: {exc})_\n"


def save_runbook(alert_id: str, markdown: str) -> Path:
    """Persist the runbook to runbooks/output/ and return its path."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = OUTPUT_DIR / f"{alert_id}_{ts}.md"
    path.write_text(markdown, encoding="utf-8")
    return path
