"""Benchmark: one simulated month of a depository with attacks mixed in.

    python -m backend.bench --accounts 10000 --days 30 --attacks 60

Reports, per attack type and variant, how many incidents AgentSnap stopped before
the loss, and on everyday traffic how often it held or challenged a legitimate
investor. A naive amount-threshold policy runs on the same events for comparison.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import time
from collections import Counter, defaultdict
from pathlib import Path

from .engine import Engine
from .sim import ATTACK_KINDS, DAY, T0, World

PROTECTED = {"offmarket_out", "edis_auth", "pledge_create", "mf_redeem", "contact_change", "beneficiary_add", "ddpi_register"}
STOP = {"hold", "block"}


def naive(e):
    """A plausible 'just add a limit' policy: hold anything large."""
    a = e.attrs
    if e.type == "offmarket_out" and a.get("value", 0) >= 200000:
        return "hold"
    if e.type == "edis_auth" and a.get("value", 0) >= 500000:
        return "hold"
    if e.type == "pledge_create" and a.get("value", 0) >= 1000000:
        return "hold"
    return "allow"


def pct(xs, q):
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = min(len(xs) - 1, max(0, int(round(q / 100 * (len(xs) - 1)))))
    return xs[k]


def run(accounts=10000, days=30, attacks=60, seed=7, policy=None, reference=False, quiet=False, optin=0.0):
    rng = random.Random(seed + 1)
    eng = Engine(policy, reference=reference)
    w = World(eng, seed, optin)
    w.populate(accounts)
    w.make_mules(max(30, int(len(ATTACK_KINDS) * attacks * 0.6)))  # each mule is reused ~1.7 times
    benign = w.benign_events(days)
    incidents = []
    for kind in ATTACK_KINDS:
        for _ in range(attacks):
            inc = w.attack(kind, T0 + rng.uniform(2 * DAY, (days - 1) * DAY))
            if inc:
                incidents.append(inc)
    atk_event = {e.id: inc for inc in incidents for e in inc.events}
    events = sorted(benign + [e for inc in incidents for e in inc.events], key=lambda e: e.ts)

    dec, lat = {}, []
    t_start = time.perf_counter()
    for e in events:
        d = eng.process(e)
        dec[e.id] = d
        lat.append(d.latency_us)
        if d.action == "hold":
            if e.id in atk_event:
                eng.act_on_hold(d.hold_id, "guardian_decline", "sim")
            else:
                eng.act_on_hold(d.hold_id, "release", "sim")
    wall = time.perf_counter() - t_start
    eng.audit.flush()

    # ---------------------------------------------------------------- attacks
    by = defaultdict(lambda: {"n": 0, "stopped": 0, "challenged": 0, "value": 0.0, "value_stopped": 0.0})
    rule_cov = Counter()
    first_stop_step = []
    for inc in incidents:
        stopped = False
        challenged = False
        for i, e in enumerate(inc.events):
            d = dec[e.id]
            for h in d.hits:
                rule_cov[h["id"]] += 1
            if d.action in STOP and (e.id in inc.theft or d.action == "block"):
                stopped = True
                first_stop_step.append(i + 1)
                break
            if e.id in inc.theft and d.action == "step_up":
                challenged = True
        for key in (inc.kind, f"{inc.kind}/{inc.variant}"):
            b = by[key]
            b["n"] += 1
            b["stopped"] += stopped
            b["challenged"] += (challenged and not stopped)
            b["value"] += inc.value
            b["value_stopped"] += inc.value if stopped else 0
        inc._stopped = stopped
    naive_stop = sum(any(naive(e) in STOP for e in inc.events if e.id in inc.theft) for inc in incidents)

    # ---------------------------------------------------------------- benign
    ben = [e for e in benign if e.type in PROTECTED]
    fh = [e for e in ben if dec[e.id].action in STOP]
    su = [e for e in ben if dec[e.id].action == "step_up"]
    fh_rules = Counter(h["id"] for e in fh for h in dec[e.id].hits if h["action"].startswith(("hold", "block")))
    su_rules = Counter(h["id"] for e in su for h in dec[e.id].hits)
    naive_fh = sum(naive(e) in STOP for e in ben)
    n_benign_accounts = sum(1 for p in w.people.values() if p.acct.label == "benign")
    month = days / 30

    total_inc = len(incidents)
    stopped = sum(1 for i in incidents if i._stopped)
    out = {
        "config": {"accounts": accounts, "mule_accounts": len(w.mules), "days": days, "attacks_per_kind": attacks, "seed": seed,
                   "events": len(events), "benign_protected_events": len(ben), "rules": len(eng.rules),
                   "monitors": "reference" if reference else "incremental"},
        "attacks": {
            "incidents": total_inc, "stopped": stopped, "stopped_pct": round(100 * stopped / total_inc, 1),
            "value": round(sum(i.value for i in incidents)), "value_stopped": round(sum(i.value for i in incidents if i._stopped)),
            "by_kind": {k: {**v, "stopped_pct": round(100 * v["stopped"] / v["n"], 1)} for k, v in sorted(by.items())},
            "median_stop_step": statistics.median(first_stop_step) if first_stop_step else None,
            "rules_fired_on_attacks": dict(rule_cov.most_common()),
        },
        "benign": {
            "protected_events": len(ben), "false_holds": len(fh), "false_hold_pct": round(100 * len(fh) / max(1, len(ben)), 3),
            "step_ups": len(su), "step_up_pct": round(100 * len(su) / max(1, len(ben)), 2),
            "false_holds_per_1k_accounts_month": round(1000 * len(fh) / n_benign_accounts / month, 2),
            "false_hold_rules": dict(fh_rules.most_common()), "step_up_rules": dict(su_rules.most_common()),
            "false_hold_by_type": dict(Counter(e.type for e in fh).most_common()),
        },
        "naive_threshold": {
            "stopped": naive_stop, "stopped_pct": round(100 * naive_stop / total_inc, 1),
            "false_holds": naive_fh, "false_hold_pct": round(100 * naive_fh / max(1, len(ben)), 3),
        },
        "latency_us": {"p50": round(pct(lat, 50), 1), "p95": round(pct(lat, 95), 1), "p99": round(pct(lat, 99), 1),
                        "max": round(max(lat), 1), "mean": round(statistics.fmean(lat), 1)},
        "throughput_events_per_s": round(len(events) / wall),
        "wall_s": round(wall, 2),
        "audit": eng.audit.verify(),
    }
    if not quiet:
        print(summary(out))
    return out, eng, w, incidents


def summary(o):
    a, b, n, l = o["attacks"], o["benign"], o["naive_threshold"], o["latency_us"]
    lines = [
        f"{o['config']['events']:,} events, {o['config']['accounts']:,} accounts, {o['config']['days']} days, {o['config']['rules']} rules ({o['config']['monitors']})",
        f"attacks stopped before loss: {a['stopped']}/{a['incidents']} ({a['stopped_pct']}%), value {a['value_stopped']:,}/{a['value']:,}",
    ]
    for k, v in a["by_kind"].items():
        if "/" in k:
            lines.append(f"   {k:34s} {v['stopped']:3d}/{v['n']:<3d} {v['stopped_pct']:5.1f}%  challenged {v['challenged']}")
    lines += [
        f"benign protected events: {b['protected_events']:,}; false holds {b['false_holds']} ({b['false_hold_pct']}%), "
        f"{b['false_holds_per_1k_accounts_month']} per 1k accounts per month; step-ups {b['step_ups']} ({b['step_up_pct']}%)",
        f"   false-hold rules: {b['false_hold_rules']}",
        f"   step-up rules: {b['step_up_rules']}",
        f"naive threshold: stopped {n['stopped_pct']}% of attacks, false holds {n['false_holds']} ({n['false_hold_pct']}%)",
        f"latency us p50 {l['p50']} p95 {l['p95']} p99 {l['p99']} max {l['max']}; {o['throughput_events_per_s']:,} events/s; audit {o['audit']}",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--accounts", type=int, default=10000)
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--attacks", type=int, default=60)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--reference", action="store_true")
    ap.add_argument("--optin", type=float, default=0.0, help="share of seniors with a guardian who opt in to the new-beneficiary lock")
    ap.add_argument("--policy", help="ASPL file; default policies/default.aspl")
    ap.add_argument("--out", default="results/benchmark.json")
    args = ap.parse_args()
    src = Path(args.policy).read_text(encoding="utf8") if args.policy else None
    o, *_ = run(args.accounts, args.days, args.attacks, args.seed, policy=src, reference=args.reference, optin=args.optin)
    o["config"]["policy"] = args.policy or "policies/default.aspl"
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(o, indent=1, default=str))
    print("wrote", args.out)
