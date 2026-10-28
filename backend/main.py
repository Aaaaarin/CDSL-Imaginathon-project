"""AgentSnap API and console server.

    python -m uvicorn backend.main:app --port 8740
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import random
import threading
from collections import deque
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import aspl, api_v1
from .domain import EVENT_TYPES
from .engine import Engine, POLICY_DIR, PolicyRejected, compile_policy
from .scenarios import SCENARIOS, catalogue, replay, s_digital_arrest, _world
from .sim import ATTACK_KINDS, DAY, T0, World
from .telemetry import SIGNALS

ROOT = Path(__file__).resolve().parent.parent
FRONT = ROOT / "frontend"
RESULTS = ROOT / "results"

@contextlib.asynccontextmanager
async def lifespan(_app):
    yield
    shutdown()


app = FastAPI(title="AgentSnap", version="1.0", lifespan=lifespan,
              description="Investor-safety layer for depository events. Integration API under /v1; console under /api (localhost only).")
CONSOLE_OPEN = os.environ.get("AGENTSNAP_CONSOLE_OPEN") == "1"
LOCK = threading.RLock()  # the engine is single-writer; every path that touches it takes this


class ConsoleLocalhostOnly:
    """The console API has no auth of its own, so it only answers on localhost
    unless AGENTSNAP_CONSOLE_OPEN=1. The /v1 API carries its own key-based auth.
    Plain ASGI rather than BaseHTTPMiddleware, which costs a task per request."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"].startswith("/api/") and not CONSOLE_OPEN:
            host = (scope.get("client") or ("", 0))[0]
            if host not in ("127.0.0.1", "::1", "localhost", "testclient"):
                await JSONResponse({"error": "console API is restricted to localhost"}, 403)(scope, receive, send)
                return
        await self.app(scope, receive, send)


class Hardening:
    """Request-size cap (1 MB, larger bodies are refused before parsing) and
    security headers on every response."""
    MAX = 1_000_000
    HEADERS = [
        (b"x-content-type-options", b"nosniff"), (b"x-frame-options", b"DENY"), (b"referrer-policy", b"no-referrer"),
        (b"content-security-policy", b"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                                     b"script-src 'self'; connect-src 'self' ws: wss:; frame-ancestors 'none'"),
        (b"cache-control", b"no-store"),
    ]

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        size = dict(scope.get("headers") or []).get(b"content-length")
        if size and int(size) > self.MAX:
            return await JSONResponse({"error": "request body too large"}, 413)(scope, receive, send)

        extra = self.HEADERS if not scope["path"].startswith(("/docs", "/redoc")) else self.HEADERS[:3]  # Swagger UI loads from a CDN

        async def send_h(msg):
            if msg["type"] == "http.response.start":
                msg["headers"] = list(msg.get("headers") or []) + extra
            await send(msg)
        await self.app(scope, receive, send_h)


app.add_middleware(ConsoleLocalhostOnly)
app.add_middleware(Hardening)


# ------------------------------------------------------------------ live world
class Live:
    def __init__(self):
        self.clients: set[WebSocket] = set()
        self.task = None
        self.speed = 40  # events per second
        self.reset()

    def reset(self):
        self.recent = deque(maxlen=200)
        self.alerts = deque(maxlen=100)
        self.eng = Engine(listeners=[self._on_decision])
        self.world = World(self.eng, seed=11)
        self.world.populate(2500)
        self.world.make_mules(60)
        rng = random.Random(5)
        benign = self.world.benign_events(30)
        self.incidents = {}
        atk = []
        for kind in ATTACK_KINDS:
            for _ in range(6):
                inc = self.world.attack(kind, T0 + rng.uniform(1 * DAY, 29 * DAY))
                for e in inc.events:
                    self.incidents[e.id] = inc
                atk += inc.events
        self.queue = deque(sorted(benign + atk, key=lambda e: e.ts))
        self.total = len(self.queue)
        self.clock = T0
        self.outbox = deque(maxlen=400)

    def _on_decision(self, d, e):
        row = {"seq": d.seq, "ts": d.ts, "bo": d.bo, "etype": d.etype, "action": d.action,
               "rules": [h["id"] for h in d.hits], "value": e.attrs.get("value"), "attack": e.id in self.incidents,
               "kind": self.incidents[e.id].kind if e.id in self.incidents else None, "hold_id": getattr(d, "hold_id", None),
               "latency_us": round(d.latency_us, 1)}
        self.recent.appendleft(row)
        if d.action != "allow":
            self.alerts.appendleft({**row, "hits": d.hits, "telemetry": getattr(d, "telemetry", [])})
        self.outbox.append(row)

    def step(self, n):
        with LOCK:
            for _ in range(min(n, len(self.queue))):
                e = self.queue.popleft()
                self.clock = e.ts
                self.eng.process(e)

    def state(self):
        s = self.eng.stats
        return {"clock": self.clock, "processed": s["events"], "total": self.total, "running": self.task is not None and not self.task.done(),
                "counts": {k: s[k] for k in ("allow", "step_up", "hold", "block")}, "speed": self.speed,
                "accounts": len(self.eng.accounts), "holds_pending": sum(1 for x in self.eng.holds.values() if x.status == "pending")}

    async def run(self):
        while self.queue:
            self.step(max(1, self.speed // 10))
            if self.outbox and self.clients:
                rows = list(self.outbox)
                self.outbox.clear()
                msg = json.dumps({"type": "batch", "rows": [r for r in rows if r["action"] != "allow"] + rows[-6:], "state": self.state()}, default=str)
                for ws in list(self.clients):
                    try:
                        await ws.send_text(msg)
                    except Exception:
                        self.clients.discard(ws)
            await asyncio.sleep(0.1)


live = Live()
api_v1.bind(lambda: live.eng, LOCK)
app.include_router(api_v1.router)


def shutdown():
    """Graceful stop: drain the event log and sign the final audit head."""
    with LOCK:
        live.eng.events.flush()
        live.eng.audit.close()


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/readyz")
def readyz():
    eng = live.eng
    providers = eng.telemetry.health()
    ready = bool(eng.rules)
    try:
        eng.audit.flush()
    except Exception:
        ready = False
    body = {"ready": ready, "policy": eng.active.version, "providers": providers,
            "degraded": [p["name"] for p in providers if p["state"] == "open"]}
    return JSONResponse(body, 200 if ready else 503)


@app.get("/metrics")
def metrics():
    eng = live.eng
    g = eng.gauges()
    g.update({f'provider_open{{name="{p["name"]}"}}': int(p["state"] == "open") for p in eng.telemetry.health()})
    return PlainTextResponse(eng.metrics.prometheus(g))


# ------------------------------------------------------------------ models
class PolicyIn(BaseModel):
    source: str


class ReplayIn(BaseModel):
    source: str | None = None


# ------------------------------------------------------------------ routes
@app.get("/")
def index():
    return FileResponse(FRONT / "index.html")


@app.get("/api/meta")
def meta():
    return {"event_types": {k: {"desc": v[0], "attrs": v[1]} for k, v in EVENT_TYPES.items()},
            "signals": [{"name": n, "tier": t, "source": s, "privacy": p} for n, t, s, p in SIGNALS]}


@app.get("/api/scenarios")
def scenarios():
    return catalogue()


@app.post("/api/replay/{sid}")
def do_replay(sid: str, body: ReplayIn | None = None):
    if sid not in SCENARIOS:
        return JSONResponse({"error": "unknown scenario"}, 404)
    try:
        return replay(sid, body.source if body and body.source else None)
    except aspl.ASPLError as e:
        return JSONResponse({"error": str(e), "line": e.line, "col": e.col}, 400)


def describe(rules):
    out = []
    for r in rules:
        layouts = []
        for n in r.temporals():
            if isinstance(n, aspl.Since):
                layouts.append({"node": f"since({n.btype}, {n.atype})", "layout": "boolean state per account", "cost": "O(1)"})
            elif n.buffered:
                layouts.append({"node": n.label(), "layout": "bounded buffer", "cost": "O(events in window)"})
            elif n.slice_field:
                layouts.append({"node": n.label(), "layout": f"sliced by {n.slice_field}", "cost": "O(1) amortised"})
            else:
                layouts.append({"node": n.label(), "layout": "sliding window", "cost": "O(1) amortised" if n.lo == 0 else "O(window)"})
        out.append({"id": r.id, "name": r.name, "on": r.on, "action": r.action.text(), "tags": r.tags,
                    "explain": r.explain, "lesson": r.lesson, "source": r.source, "monitors": layouts})
    return out


@app.get("/api/policy")
def get_policy():
    return {"source": live.eng.policy_src, "rules": describe(live.eng.rules)}


@app.post("/api/policy/compile")
def compile_endpoint(p: PolicyIn):
    try:
        rules, issues = compile_policy(p.source, strict=False)
    except aspl.ASPLError as e:
        return JSONResponse({"ok": False, "error": str(e), "line": e.line, "col": e.col}, 400)
    errors = [i for i in issues if i["level"] == "error"]
    if errors:
        return JSONResponse({"ok": False, "error": f"{errors[0]['rule']}: {errors[0]['msg']}", "line": errors[0]["line"],
                             "issues": issues}, 400)
    return {"ok": True, "rules": describe(rules), "issues": issues, "warnings": [i["msg"] for i in issues if i["level"] == "warning"]}


@app.post("/api/policy/shadow")
def policy_shadow(p: PolicyIn):
    try:
        with LOCK:
            live.eng.deploy_shadow(p.source, "from console")
    except aspl.ASPLError as e:
        return JSONResponse({"ok": False, "error": str(e), "line": e.line}, 400)
    return {"ok": True, "shadow": api_v1.shadow_status(live.eng)}


@app.post("/api/policy/promote")
def policy_promote():
    with LOCK:
        if not live.eng.shadow:
            return JSONResponse({"error": "no shadow policy"}, 409)
        live.eng.promote_shadow()
    return {"ok": True, "active": live.eng.active.version, "history": live.eng.policy_history}


@app.delete("/api/policy/shadow")
def policy_discard():
    live.eng.discard_shadow()
    return {"ok": True}


# ------------------------------------------------------------------ operations
@app.get("/api/ops")
def ops():
    eng = live.eng
    m = eng.metrics
    return {"gauges": eng.gauges(), "providers": eng.telemetry.health(), "policy": {"active": eng.active.version,
            "history": eng.policy_history, "shadow": api_v1.shadow_status(eng)},
            "latency_us": {"p50_bucket": m.quantile(0.5), "p99_bucket": m.quantile(0.99), "buckets": list(zip([str(b) for b in m.BUCKETS], m.lat))},
            "counters": dict(m.c), "rule_hits": dict(sorted(m.rule_hits.items(), key=lambda x: -x[1])[:12]),
            "last_snapshot": getattr(eng, "last_snapshot", None), "public_key": eng.audit.public_key_pem()}


@app.post("/api/ops/snapshot")
def ops_snapshot():
    with LOCK:
        return api_v1.take_snapshot(live.eng)


@app.post("/api/ops/drill")
def ops_drill():
    with LOCK:
        try:
            return api_v1.recovery_drill(live.eng)
        except Exception as e:  # HTTPException from the drill when no snapshot exists
            return JSONResponse({"error": getattr(e, "detail", str(e))}, 409)


@app.post("/api/ops/provider/{name}/{state}")
def ops_provider(name: str, state: str):
    if state not in ("up", "down"):
        return JSONResponse({"error": "state is up or down"}, 400)
    return api_v1.set_provider(live.eng, name, state)


@app.post("/api/policy/test")
def test_policy(p: PolicyIn):
    """Run every scenario under a candidate policy and report where each one stops."""
    try:
        compile_policy(p.source)
    except aspl.ASPLError as e:
        return JSONResponse({"ok": False, "error": str(e), "line": e.line, "col": e.col}, 400)
    out = []
    for sid in SCENARIOS:
        r = replay(sid, p.source)
        out.append({"id": sid, "title": r["title"], "stopped_at": r["stopped_at"], "steps": len(r["steps"]),
                    "actions": [s["decision"]["action"] for s in r["steps"]]})
    return {"ok": True, "scenarios": out}


@app.get("/api/benchmark")
def benchmark():
    def load(name):
        f = RESULTS / name
        return json.loads(f.read_text()) if f.exists() else None
    return {"v2": load("benchmark.json"), "v1": load("benchmark-v1.json"), "optin": load("benchmark-optin.json"),
            "microbench": load("microbench.json")}


# ------------------------------------------------------------------ live
@app.get("/api/live/state")
def live_state():
    return {"state": live.state(), "recent": list(live.recent)[:60], "alerts": list(live.alerts)[:40]}


@app.post("/api/live/start")
async def live_start(speed: int = 40):
    live.speed = max(5, min(speed, 2000))
    if live.task is None or live.task.done():
        live.task = asyncio.create_task(live.run())
    return live.state()


@app.post("/api/live/stop")
async def live_stop():
    if live.task:
        live.task.cancel()
        live.task = None
    return live.state()


@app.post("/api/live/reset")
async def live_reset():
    await live_stop()
    live.reset()
    return live.state()


@app.websocket("/ws")
async def ws(ws: WebSocket):
    await ws.accept()
    live.clients.add(ws)
    try:
        await ws.send_text(json.dumps({"type": "hello", "state": live.state()}, default=str))
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        live.clients.discard(ws)


@app.get("/api/holds")
def holds():
    hs = sorted(live.eng.holds.values(), key=lambda x: -x.created)
    return [x.to_dict() for x in hs[:80]]


@app.post("/api/holds/{hid}/{act}")
def hold_act(hid: str, act: str):
    if act not in ("cancel", "release", "guardian_approve", "guardian_decline", "dp_confirm"):
        return JSONResponse({"error": "bad action"}, 400)
    with LOCK:
        hc = live.eng.act_on_hold(hid, act, "console")
    return hc.to_dict() if hc else JSONResponse({"error": "action not allowed in the hold's current state"}, 409)


@app.get("/api/account/{bo}")
def account(bo: str):
    a = live.eng.accounts.get(bo)
    if not a:
        return JSONResponse({"error": "unknown account"}, 404)
    rows = [r for r in live.recent if r["bo"] == bo]
    return {"account": a.view() | {"opened_ts": a.opened_ts, "label": a.label}, "graph": live.eng.graph.neighbourhood(bo),
            "features": live.eng.graph.features(bo), "mule_score": live.eng.graph.mule_score(bo), "recent": rows}


@app.get("/api/graph/rings")
def rings():
    """The accounts with the highest mule scores right now, with their neighbourhoods."""
    g = live.eng.graph
    cands = sorted({d for q in g.inflows for d in [q]}, key=g.mule_score, reverse=True)[:3]
    return [{"bo": b, "mule_score": g.mule_score(b), "graph": g.neighbourhood(b)} for b in cands]


# ------------------------------------------------------------------ investor app demo
class AppDemo:
    """One investor (Asha) and her guardian, on a dedicated engine, for the phone screens."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.eng = _world()
        self.steps = s_digital_arrest(self.eng)
        self.idx = 0
        self.decisions = []

    def next(self):
        if self.idx >= len(self.steps):
            return None
        text, e = self.steps[self.idx]
        self.idx += 1
        d = self.eng.process(e)
        row = {"text": text, "type": e.type, "attrs": e.attrs, "decision": d.to_dict(), "hold_id": getattr(d, "hold_id", None)}
        self.decisions.append(row)
        return row

    def state(self):
        hold = next((h for h in self.eng.holds.values()), None)
        return {"step": self.idx, "total": len(self.steps), "decisions": self.decisions, "hold": hold.to_dict() if hold else None,
                "lock_offmarket": self.eng.accounts["1208ASHA0072"].lock_offmarket if "1208ASHA0072" in self.eng.accounts else False}


appdemo = AppDemo()


@app.get("/api/app/state")
def app_state():
    return appdemo.state()


@app.post("/api/app/next")
def app_next():
    appdemo.next()
    return appdemo.state()


@app.post("/api/app/reset")
def app_reset():
    appdemo.reset()
    return appdemo.state()


@app.post("/api/app/hold/{act}")
def app_hold(act: str):
    hold = next((h for h in appdemo.eng.holds.values() if h.status == "pending"), None)
    if hold:
        appdemo.eng.act_on_hold(hold.id, act, "guardian" if act.startswith("guardian") else "investor")
    return appdemo.state()


@app.post("/api/app/lock/{on}")
def app_lock(on: int):
    a = appdemo.eng.accounts.get("1208ASHA0072")
    if a:
        a.lock_offmarket = bool(on)
    return appdemo.state()


# ------------------------------------------------------------------ audit
@app.get("/api/audit")
def audit():
    return {"verify": live.eng.audit.verify(), "tail": live.eng.audit.tail(30)}


@app.post("/api/audit/tamper/{seq}")
def tamper(seq: int, recompute: int = 0):
    with LOCK:
        live.eng.audit.checkpoint()  # make sure a signed checkpoint covers the record first
        ok = live.eng.audit.tamper(seq, recompute=bool(recompute))
        return {"tampered": ok, "recomputed": bool(recompute), "verify": live.eng.audit.verify()}


app.mount("/static", StaticFiles(directory=FRONT), name="static")
