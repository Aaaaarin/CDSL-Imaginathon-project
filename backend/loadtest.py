"""HTTP load test against a running server: real network, auth, schema validation,
engine, audit. Events come from the simulator.

    python -m backend.loadtest --url http://127.0.0.1:8740 --events 20000 --clients 16
"""
from __future__ import annotations

import argparse
import json
import statistics
import threading
import time
from pathlib import Path

import httpx

from .engine import Engine
from .sim import World


def events(n, seed=21):
    w = World(Engine(), seed)
    w.populate(max(200, n // 15))
    w.make_mules(20)
    out = []
    for e in sorted(w.benign_events(30), key=lambda x: x.ts)[:n]:
        out.append({"event_id": f"lt-{seed}-{e.id}", "ts": e.ts, "bo": e.bo, "type": e.type,
                    "attrs": e.attrs, "tel": {k: v for k, v in e.tel.items() if v is not None}})
    return out


def run(url, n, clients, key, batch, seed=21):
    evs = events(n, seed)
    chunks = [evs[i::clients] for i in range(clients)]
    lat, codes, lock = [], {}, threading.Lock()

    def worker(chunk):
        with httpx.Client(base_url=url, headers={"X-API-Key": key}, timeout=30) as c:
            i = 0
            while i < len(chunk):
                t = time.perf_counter()
                if batch > 1:
                    r = c.post("/v1/events:batch", json={"events": chunk[i:i + batch]})
                    i += batch
                else:
                    r = c.post("/v1/events", json=chunk[i])
                    i += 1
                dt = (time.perf_counter() - t) * 1000
                with lock:
                    lat.append(dt)
                    codes[r.status_code] = codes.get(r.status_code, 0) + 1

    t0 = time.perf_counter()
    ts = [threading.Thread(target=worker, args=(ch,)) for ch in chunks]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    wall = time.perf_counter() - t0
    lat.sort()
    q = lambda p: round(lat[min(len(lat) - 1, int(p * len(lat)))], 2)
    res = {"events": len(evs), "clients": clients, "batch": batch, "wall_s": round(wall, 2),
           "events_per_s": round(len(evs) / wall), "requests": len(lat), "status_codes": codes,
           "latency_ms": {"p50": q(0.5), "p95": q(0.95), "p99": q(0.99), "mean": round(statistics.fmean(lat), 2)}}
    print(json.dumps(res, indent=1))
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8740")
    ap.add_argument("--events", type=int, default=20000)
    ap.add_argument("--clients", type=int, default=16)
    ap.add_argument("--batch", type=int, default=1)
    ap.add_argument("--key", default="dev-key")
    ap.add_argument("--seed", type=int, default=21)
    ap.add_argument("--out")
    a = ap.parse_args()
    out = run(a.url, a.events, a.clients, a.key, a.batch, a.seed)
    Path("results").mkdir(exist_ok=True)
    name = a.out or ("loadtest.json" if a.batch == 1 else "loadtest-batch.json")
    Path("results", name).write_text(json.dumps(out, indent=1))
