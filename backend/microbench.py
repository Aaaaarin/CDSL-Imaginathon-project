"""Per-event cost as one account's history grows: incremental monitors vs reference.

    python -m backend.microbench
"""
from __future__ import annotations

import json
import random
import time
from pathlib import Path

from .domain import Account
from .engine import Engine, new_event

SIZES = [1000, 5000, 20000, 50000]


def stream(rng, n, t0=0.0):
    t = t0
    for i in range(n):
        t += rng.uniform(30, 900)  # an active trader: an event every few minutes
        typ = rng.choices(["session_start", "edis_auth", "offmarket_out", "beneficiary_add", "pledge_create"], [5, 6, 1, 0.3, 1])[0]
        a = {"value": rng.randint(1000, 90000), "target_bo": f"T{rng.randint(0, 30)}", "portfolio_frac": 0.01,
             "pledgee": "own_tm", "margin_need": 50000, "reason": "family", "channel": "app"}
        yield new_event("ACC", typ, t, a, {"device_age_h": 5000, "ip": "100.64.1.1"})


def measure(reference, n, probe=1500, seed=3, repeats=3):
    import statistics
    return statistics.median(_measure(reference, n, probe, seed + r) for r in range(repeats))


def _measure(reference, n, probe, seed):
    rng = random.Random(seed)
    eng = Engine(reference=reference)
    eng.add_account(Account("ACC", "trader", 40, 0, cap_offmarket=10**9, daily_cap=10**12))
    evs = list(stream(rng, n + probe))
    for e in evs[:n]:
        eng.process(e, settle=False)
    t = time.perf_counter()
    for e in evs[n:]:
        eng.process(e, settle=False)
    return (time.perf_counter() - t) / probe * 1e6


if __name__ == "__main__":
    rows = []
    for n in SIZES:
        inc = measure(False, n)
        ref = measure(True, n)
        rows.append({"history": n, "incremental_us": round(inc, 1), "reference_us": round(ref, 1), "speedup": round(ref / inc, 1)})
        print(rows[-1])
    Path("results").mkdir(exist_ok=True)
    Path("results/microbench.json").write_text(json.dumps(rows, indent=1))
