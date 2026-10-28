"""Measure the policy on real history without sharing it.

A DP or broker exports its own past events (JSON lines in the /v1/events schema)
and runs this on its own machine. Nothing leaves the machine; the output is a count
of what AgentSnap would have done. Holds on accounts that were never defrauded are
the false-hold rate; holds that line up with known fraud complaints are catches.

    python -m backend.shadow_replay events.jsonl [--accounts accounts.csv] [--fraud fraud_bos.txt]

accounts.csv (optional): bo,persona,age_years,cap_offmarket,daily_cap,guardian,opened_ts
fraud_bos.txt (optional): one BO per line that filed a fraud complaint
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

from . import aspl
from .api_v1 import EventIn
from .domain import Account
from .engine import Engine

PROTECTED = {"offmarket_out", "edis_auth", "pledge_create", "mf_redeem", "contact_change", "beneficiary_add", "ddpi_register"}


def load_accounts(path):
    out = []
    with open(path, newline="", encoding="utf8") as f:
        for r in csv.DictReader(f):
            out.append(Account(r["bo"], r.get("persona", "first_time"), int(r.get("age_years") or 40), float(r.get("opened_ts") or 0),
                               cap_offmarket=float(r.get("cap_offmarket") or 200000), daily_cap=float(r.get("daily_cap") or 500000),
                               guardian=str(r.get("guardian", "")).lower() in ("1", "true", "yes")))
    return out


def run(events_path, accounts_path=None, fraud_path=None, policy=None):
    eng = Engine(policy)
    for a in load_accounts(accounts_path) if accounts_path else []:
        eng.add_account(a)
    fraud = set(Path(fraud_path).read_text().split()) if fraud_path else set()
    rejected, actions, rules, held_bos = Counter(), Counter(), Counter(), set()
    protected = stopped_benign = 0
    rows = []
    with open(events_path, encoding="utf8") as f:
        for i, line in enumerate(f):
            if not line.strip():
                continue
            try:
                ev = EventIn.model_validate_json(line)
            except Exception as e:
                rejected[str(e).split("\n")[1].strip() if "\n" in str(e) else "invalid"] += 1
                continue
            rows.append(ev)
    for ev in sorted(rows, key=lambda x: x.ts):
        d = eng.process(aspl.Event(ev.event_id, ev.ts, ev.bo, ev.type, dict(ev.attrs), ev.tel.model_dump(exclude_none=True)))
        if d.action == "hold":
            eng.act_on_hold(d.hold_id, "release", "shadow")   # shadow: nothing is ever actually paused
        actions[d.action] += 1
        for h in d.hits:
            rules[h["id"]] += 1
        if ev.type in PROTECTED:
            protected += 1
            if d.action in ("hold", "block"):
                held_bos.add(ev.bo)
                if ev.bo not in fraud:
                    stopped_benign += 1
    report = {
        "events": len(rows), "rejected": dict(rejected), "actions": dict(actions), "rules": dict(rules.most_common()),
        "protected_events": protected, "holds_on_accounts_without_fraud": stopped_benign,
        "false_hold_rate": round(stopped_benign / protected, 5) if protected else None,
        "fraud_accounts": len(fraud), "fraud_accounts_held": len(held_bos & fraud),
        "policy": eng.active.version,
    }
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("events")
    ap.add_argument("--accounts")
    ap.add_argument("--fraud")
    ap.add_argument("--policy")
    a = ap.parse_args()
    src = Path(a.policy).read_text(encoding="utf8") if a.policy else None
    json.dump(run(a.events, a.accounts, a.fraud, src), sys.stdout, indent=1)
    print()
