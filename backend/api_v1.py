"""Versioned integration API for depository participants, broker apps and ops.

Auth: X-API-Key header. Keys come from AGENTSNAP_API_KEYS as
"name:key:role1+role2,..." with roles ingest, analyst, admin. Without it a single
development key is enabled and a warning is logged.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import aspl
from .domain import EVENT_TYPES
from .engine import Engine, PolicyRejected, compile_policy, lint_policy

log = logging.getLogger("agentsnap.api")
router = APIRouter(prefix="/v1")

_get_engine: Callable[[], Engine] = lambda: None  # set by bind()
_lock = threading.RLock()
DATA = Path(os.environ.get("AGENTSNAP_DATA", Path(__file__).resolve().parent.parent / "data"))


def bind(get_engine, lock):
    global _get_engine, _lock
    _get_engine, _lock = get_engine, lock


# ------------------------------------------------------------------ auth and rate limit
def _load_keys():
    raw = os.environ.get("AGENTSNAP_API_KEYS")
    if not raw:
        log.warning("AGENTSNAP_API_KEYS not set: using the development key 'dev-key' with all roles")
        raw = "dev:dev-key:ingest+analyst+admin"
    keys = {}
    for part in raw.split(","):
        name, key, roles = part.split(":")
        keys[hashlib.sha256(key.encode()).hexdigest()] = (name, set(roles.split("+")))
    return keys


KEYS = _load_keys()


class _Bucket:
    def __init__(self, rate=5000, burst=10000):
        self.rate, self.burst, self.tokens, self.t = rate, burst, burst, time.monotonic()

    def take(self):
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.t) * self.rate)
        self.t = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


_buckets: dict[str, _Bucket] = {}


async def caller(x_api_key: str | None = Header(default=None)):  # async: no thread-pool hop per request
    if not x_api_key:
        raise HTTPException(401, "missing X-API-Key")
    digest = hashlib.sha256(x_api_key.encode()).hexdigest()
    match = next((v for k, v in KEYS.items() if hmac.compare_digest(k, digest)), None)
    if not match:
        raise HTTPException(401, "invalid API key")
    name, roles = match
    b = _buckets.setdefault(name, _Bucket())
    if not b.take():
        raise HTTPException(429, "rate limit exceeded")
    return {"name": name, "roles": roles}


def need(role):
    async def dep(c=Depends(caller)):
        if role not in c["roles"]:
            raise HTTPException(403, f"needs role '{role}'")
        return c
    return dep


# ------------------------------------------------------------------ schemas
REQUIRED = {
    "contact_change": ["field", "channel"], "beneficiary_add": ["target_bo"], "ddpi_register": ["tm"],
    "edis_auth": ["value"], "offmarket_out": ["target_bo", "value"], "offmarket_in": ["source_bo", "value"],
    "pledge_create": ["pledgee", "value", "margin_need"], "mf_redeem": ["value", "bank"], "sale_settle": ["value"],
}
BO_RE = r"^[0-9A-Z]{8,20}$"
Scalar = str | float | int | bool | None


class TelemetryIn(BaseModel):
    """What the AgentSnap SDK sends. Numbers are hashed on the device; no content, no audio."""
    model_config = ConfigDict(extra="forbid")
    device_id: str | None = Field(None, max_length=64)
    device_age_h: float | None = Field(None, ge=0)
    attested: bool | None = None
    device_sim_h: str | None = Field(None, max_length=64)
    ip: str | None = Field(None, max_length=45)
    call_active: bool | None = None
    caller_h: str | None = Field(None, max_length=64)
    caller_in_contacts: bool | None = None
    call_secs: int | None = Field(None, ge=0, le=86400)
    screen_share: bool | None = None
    remote_access_app: bool | None = None
    accessibility_overlay: bool | None = None
    paste_beneficiary: bool | None = None
    hesitation_z: float | None = Field(None, ge=-20, le=20)


class EventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(pattern=r"^[A-Za-z0-9_.:\-]{1,64}$")
    ts: float = Field(ge=1_000_000_000, le=4_000_000_000, description="event time, epoch seconds")
    bo: str = Field(pattern=BO_RE)
    type: Literal[tuple(EVENT_TYPES)]  # type: ignore[valid-type]
    attrs: dict[str, Scalar] = Field(default_factory=dict, max_length=16)
    tel: TelemetryIn = Field(default_factory=TelemetryIn)

    @model_validator(mode="after")
    def check_attrs(self):
        allowed = set(EVENT_TYPES[self.type][1])
        unknown = sorted(set(self.attrs) - allowed)
        if unknown:
            raise ValueError(f"'{self.type}' does not take {unknown}; allowed {sorted(allowed)}")
        missing = [k for k in REQUIRED.get(self.type, []) if self.attrs.get(k) is None]
        if missing:
            raise ValueError(f"'{self.type}' requires {missing}")
        v = self.attrs.get("value")
        if v is not None and (not isinstance(v, (int, float)) or isinstance(v, bool) or v < 0):
            raise ValueError("value must be a non-negative number")
        for k in ("target_bo", "source_bo"):
            if k in self.attrs and not (isinstance(self.attrs[k], str) and __import__("re").match(BO_RE, self.attrs[k])):
                raise ValueError(f"{k} must be a BO id")
        return self


class Batch(BaseModel):
    events: list[EventIn] = Field(max_length=500)


class HoldAction(BaseModel):
    action: Literal["cancel", "guardian_approve", "guardian_decline", "release", "dp_confirm"]
    actor: str = Field(max_length=64)


class PolicyIn(BaseModel):
    source: str = Field(max_length=200_000)
    note: str = Field("", max_length=200)


def decision_out(d, lang="en"):
    msgs = []
    for h in d.hits:
        if h["action"].startswith(("hold", "block")):
            t = h.get("i18n", {}).get(lang, {}) if lang != "en" else {}
            msgs.append({"rule": h["id"], "explain": t.get("explain", h["explain"]), "lesson": t.get("lesson", h["lesson"])})
    return {
        "event_id": d.event_id, "bo": d.bo, "type": d.etype, "action": d.action, "hold_secs": d.hold_secs,
        "guardian": d.guardian, "hold_id": getattr(d, "hold_id", None), "rules": [h["id"] for h in d.hits],
        "investor_message": msgs, "flags": getattr(d, "flags", []), "policy": getattr(d, "policy", None),
        "shadow": getattr(d, "shadow", None), "latency_us": round(d.latency_us, 1), "audit": {"seq": d.seq, "hash": d.hash},
    }


# ------------------------------------------------------------------ events
@router.post("/events")
async def ingest(ev: EventIn, response: Response, lang: Literal["en", "hi"] = "en", c=Depends(need("ingest"))):
    eng = _get_engine()
    with _lock:
        replay = ev.event_id in eng.seen
        d = eng.process(aspl.Event(ev.event_id, ev.ts, ev.bo, ev.type, dict(ev.attrs), ev.tel.model_dump(exclude_none=True)))
    if replay:
        response.headers["Idempotent-Replay"] = "true"
    return decision_out(d, lang)


@router.post("/events:batch")
async def ingest_batch(b: Batch, lang: Literal["en", "hi"] = "en", c=Depends(need("ingest"))):
    eng = _get_engine()
    out = []
    with _lock:
        for ev in sorted(b.events, key=lambda x: x.ts):
            out.append(decision_out(eng.process(aspl.Event(ev.event_id, ev.ts, ev.bo, ev.type, dict(ev.attrs),
                                                           ev.tel.model_dump(exclude_none=True))), lang))
    return {"decisions": out}


@router.get("/decisions/{event_id}")
def get_decision(event_id: str, lang: Literal["en", "hi"] = "en", c=Depends(need("analyst"))):
    d = _get_engine().seen.get(event_id)
    if d is None:
        raise HTTPException(404, "unknown event id (or older than the idempotency window)")
    return decision_out(d, lang)


# ------------------------------------------------------------------ holds
@router.get("/holds")
def list_holds(status: str | None = None, limit: int = 100, c=Depends(need("analyst"))):
    hs = [h for h in _get_engine().holds.values() if status is None or h.status == status]
    hs.sort(key=lambda h: -h.created)
    return [h.to_dict() for h in hs[: min(limit, 1000)]]


@router.get("/holds/{hid}")
def get_hold(hid: str, c=Depends(need("analyst"))):
    h = _get_engine().holds.get(hid)
    if not h:
        raise HTTPException(404, "unknown hold")
    return h.to_dict()


@router.post("/holds/{hid}/actions")
def hold_action(hid: str, a: HoldAction, c=Depends(caller)):
    if a.action == "dp_confirm" and not ({"analyst", "admin"} & c["roles"]):
        raise HTTPException(403, "dp_confirm needs role 'analyst'")
    eng = _get_engine()
    with _lock:
        if hid not in eng.holds:
            raise HTTPException(404, "unknown hold")
        before = eng.holds[hid].status
        h = eng.act_on_hold(hid, a.action, f"{c['name']}:{a.actor}")
    if h is None:
        raise HTTPException(409, f"'{a.action}' is not allowed when the hold is '{before}'")
    return h.to_dict()


# ------------------------------------------------------------------ policy lifecycle
def _describe(rules):
    return [{"id": r.id, "name": r.name, "on": r.on, "action": r.action.text()} for r in rules]


@router.get("/policy")
def get_policy(c=Depends(need("analyst"))):
    eng = _get_engine()
    return {"version": eng.active.version, "rules": _describe(eng.rules), "history": eng.policy_history,
            "shadow": shadow_status(eng)}


@router.post("/policy/lint")
def lint(p: PolicyIn, c=Depends(need("analyst"))):
    try:
        rules, issues = compile_policy(p.source, strict=False)
    except aspl.ASPLError as e:
        return {"ok": False, "issues": [{"level": "error", "rule": None, "line": e.line, "msg": str(e)}]}
    return {"ok": not any(i["level"] == "error" for i in issues), "rules": len(rules), "issues": issues}


def shadow_status(eng):
    if not eng.shadow:
        return None
    n, dis = eng.stats.get("shadow_events", 0), eng.stats.get("shadow_disagree", 0)
    return {"version": eng.shadow.version, "note": eng.shadow.note, "events": n, "disagreements": dis,
            "disagreement_rate": round(dis / n, 5) if n else None}


@router.post("/policy/shadow")
def deploy_shadow(p: PolicyIn, c=Depends(need("admin"))):
    eng = _get_engine()
    try:
        with _lock:
            eng.deploy_shadow(p.source, p.note)
    except PolicyRejected as e:
        raise HTTPException(422, {"error": "policy has errors", "issues": e.issues})
    except aspl.ASPLError as e:
        raise HTTPException(422, {"error": str(e), "line": e.line})
    return shadow_status(eng)


@router.post("/policy/promote")
def promote(c=Depends(need("admin"))):
    eng = _get_engine()
    with _lock:
        try:
            eng.promote_shadow()
        except ValueError as e:
            raise HTTPException(409, str(e))
    return {"active": eng.active.version, "history": eng.policy_history}


@router.delete("/policy/shadow")
def discard_shadow(c=Depends(need("admin"))):
    _get_engine().discard_shadow()
    return {"shadow": None}


# ------------------------------------------------------------------ ops
@router.post("/admin/snapshot")
def snapshot(c=Depends(need("admin"))):
    DATA.mkdir(parents=True, exist_ok=True)
    path = DATA / f"snapshot-{int(time.time())}.pkl"
    with _lock:
        return take_snapshot(_get_engine(), path)


def take_snapshot(eng, path=None):
    DATA.mkdir(parents=True, exist_ok=True)
    path = path or DATA / f"snapshot-{int(time.time() * 1000)}.pkl"
    info = eng.snapshot(str(path))
    eng.last_snapshot = info
    return info


@router.post("/admin/recovery-drill")
def drill(c=Depends(need("admin"))):
    with _lock:
        return recovery_drill(_get_engine())


@router.post("/admin/providers/{name}/{state}")
def provider(name: str, state: Literal["up", "down"], c=Depends(need("admin"))):
    return set_provider(_get_engine(), name, state)


@router.get("/privacy/export/{bo}")
def privacy_export(bo: str, c=Depends(need("analyst"))):
    """DPDP Act right to access: everything AgentSnap holds about one BO. Numbers are
    already keyed hashes; there is no raw phone number, audio or screen content to export."""
    eng = _get_engine()
    with _lock:
        a = eng.accounts.get(bo)
        if a is None:
            raise HTTPException(404, "unknown BO")
        return {
            "bo": bo, "account": a.view(), "graph": eng.graph.features(bo),
            "holds": [h.to_dict() for h in eng.holds.values() if h.event.bo == bo],
            "inputs": eng.events.for_bo(bo),
            "not_held": ["call audio", "screen contents", "contact list", "raw phone numbers", "full IP addresses"],
        }


@router.post("/admin/retention")
def retention(days: int = 180, c=Depends(need("admin"))):
    """Purge logged inputs older than `days` that the latest snapshot no longer needs."""
    eng = _get_engine()
    snap = getattr(eng, "last_snapshot", None)
    if not snap:
        raise HTTPException(409, "take a snapshot first, so purged inputs are never needed for recovery")
    cutoff = eng.graph.now - days * 86400
    with _lock:
        n = eng.events.purge_before(cutoff, keep_after_seq=snap["event_seq"])
    return {"purged": n, "older_than_days": days}


@router.get("/audit/verify")
def audit_verify(c=Depends(need("analyst"))):
    return _get_engine().audit.verify()


@router.get("/audit/public-key")
def audit_key():
    return Response(_get_engine().audit.public_key_pem(), media_type="text/plain")


def set_provider(eng, name, state):
    tgt = {"caller_registry": eng.telemetry.callers, "sim_swap": eng.telemetry.simswap,
           "number_verification": eng.telemetry.numver}.get(name)
    if tgt is None:
        raise HTTPException(404, "unknown provider")
    tgt.down = state == "down"
    if state == "up":
        eng.telemetry.breakers[name].open_until = 0
        eng.telemetry.breakers[name].fails = 0
    return eng.telemetry.health()


def state_digest(eng) -> str:
    """A fingerprint of everything that affects future decisions."""
    m = eng.active.monitors.state
    mon = sorted((f"{k[0]}|{k[1]}", _entry_len(v)) for k, v in m.items())
    summary = {"monitors": mon, "holds": sorted((h.id, h.status) for h in eng.holds.values()),
               "stats": {k: eng.stats.get(k, 0) for k in ("allow", "step_up", "hold", "block", "events")},
               "inflows": sorted((b, len(q)) for b, q in eng.graph.inflows.items()),
               "flagged": sorted(eng.graph.flagged), "last_ts": sorted(eng.last_ts.items())}
    return hashlib.sha256(json.dumps(summary, default=str).encode()).hexdigest()[:16]


def _entry_len(v):
    if hasattr(v, "q"):
        return len(v.q)
    if isinstance(v, dict):
        return sum(len(w.q) for w in v.values())
    if isinstance(v, bool):
        return int(v)
    return len(v)


def recovery_drill(eng) -> dict:
    """Crash drill. Needs a snapshot taken earlier (POST /v1/admin/snapshot). Build a
    fresh engine, give it the event log, restore the snapshot, replay everything
    logged after it, and compare state fingerprints with the running engine."""
    snap = getattr(eng, "last_snapshot", None)
    if not snap or not Path(snap["path"]).exists():
        raise HTTPException(409, "take a snapshot first, let traffic run, then run the drill")
    t0 = time.perf_counter()
    fresh = Engine(eng.active.src, signing_key=eng.audit.key)
    for _, kind, p in eng.events.after(0):
        fresh.events.append(kind, p)
    fresh.events.flush()
    rest = fresh.restore(snap["path"])
    a, b = state_digest(eng), state_digest(fresh)
    return {"snapshot_event_seq": snap["event_seq"], "log_seq": eng.events.seq, "replayed": rest["replayed"],
            "digest_running": a, "digest_restored": b, "identical": a == b,
            "ms": round((time.perf_counter() - t0) * 1000, 1)}
