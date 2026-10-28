"""Production guarantees: idempotency, ordering, failure policy, degraded telemetry,
crash recovery, bounded memory, policy checks, shadow mode, hold lifecycle,
signed audit, and the authenticated API."""
import random

import pytest
from fastapi.testclient import TestClient

from backend import aspl, api_v1
from backend.domain import Account
from backend.engine import Engine, PolicyRejected, new_event
from backend.scenarios import replay, s_digital_arrest, _world
from backend.sim import ATTACK_KINDS, DAY, T0, World
from backend.telemetry import h

UNKNOWN_CALL = {"call_active": True, "caller_h": h("scammer"), "call_secs": 900}


def senior(eng, bo="SEN00001", cap=1000):
    eng.add_account(Account(bo, "senior", 70, 0, cap_offmarket=cap, guardian=True))
    return bo


# ---------------------------------------------------------------- input handling
def test_duplicate_event_returns_original_decision():
    eng = Engine()
    bo = senior(eng)
    e = new_event(bo, "offmarket_out", 1e6, {"target_bo": "MULE0001", "value": 5000}, dict(UNKNOWN_CALL), eid="dup-1")
    d1 = eng.process(e)
    d2 = eng.process(new_event(bo, "offmarket_out", 1e6, {"target_bo": "MULE0001", "value": 5000}, dict(UNKNOWN_CALL), eid="dup-1"))
    assert d1 is d2 and eng.stats["events"] == 1 and eng.metrics.c["duplicate"] == 1
    assert len(eng.holds) == 1


def test_late_event_processed_at_account_time_and_flagged():
    eng = Engine()
    bo = senior(eng)
    eng.process(new_event(bo, "session_start", 2000, {}, {}))
    d = eng.process(new_event(bo, "session_start", 1000, {}, {}))
    assert d.ts == 2000 and any("late" in f for f in d.flags)


def test_engine_error_fails_closed_for_value_events(monkeypatch):
    eng = Engine()
    bo = senior(eng)
    monkeypatch.setattr(aspl, "evaluate_rules", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    d = eng.process(new_event(bo, "offmarket_out", 1e6, {"target_bo": "MULE0001", "value": 10}, {}))
    assert d.action == "hold" and d.hits[0]["id"] == "SYS"
    d2 = eng.process(new_event(bo, "session_start", 1e6 + 1, {}, {}))
    assert d2.action == "allow"
    assert eng.metrics.c["engine_error"] == 2


def test_caller_registry_outage_fails_closed_and_is_recorded():
    eng = Engine()
    bo = senior(eng)
    eng.telemetry.callers.down = True
    family = {"call_active": True, "caller_h": h("daughter"), "caller_in_contacts": True, "call_secs": 300}
    d = eng.process(new_event(bo, "offmarket_out", 1e6, {"target_bo": "FAM00001", "value": 5000}, dict(family)))
    assert d.action == "hold"                       # an unclassifiable caller counts as unverified
    assert any("caller_registry" in f for f in d.flags)
    for i in range(3):
        eng.process(new_event(bo, "session_start", 1e6 + i + 1, {}, dict(family)))
    assert eng.telemetry.breakers["caller_registry"].status()["state"] == "open"


# ---------------------------------------------------------------- recovery
def _world_events(eng, n_accounts=400, seed=5):
    w = World(eng, seed)
    w.populate(n_accounts)
    w.make_mules(20)
    rng = random.Random(seed)
    ev = w.benign_events(30)
    for k in ATTACK_KINDS:
        for _ in range(3):
            ev += w.attack(k, T0 + rng.uniform(2 * DAY, 28 * DAY)).events
    return sorted(ev, key=lambda e: e.ts)


def test_crash_recovery_reaches_identical_state(tmp_path):
    db = str(tmp_path / "a.db")
    a = Engine(audit_path=db)
    events = _world_events(a)
    cut = int(len(events) * 0.6)
    for e in events[:cut]:
        a.process(e)
    a.snapshot(str(tmp_path / "snap.pkl"))
    for e in events[cut:]:
        d = a.process(e)
        if d.action == "hold" and random.Random(e.id).random() < 0.5:
            a.act_on_hold(d.hold_id, "guardian_decline", "test")   # hold actions must replay too
    a.events.flush(); a.audit.flush()
    # "crash": a brand-new process opens the same database and restores
    b = Engine(audit_path=db, signing_key=a.audit.key)
    r = b.restore(str(tmp_path / "snap.pkl"))
    assert r["replayed"] > 0
    assert api_v1.state_digest(a) == api_v1.state_digest(b)
    probe = [new_event(bo, "offmarket_out", events[-1].ts + 60 + i, {"target_bo": "PROBE001", "value": 250000}, dict(UNKNOWN_CALL), eid=f"probe{i}")
             for i, bo in enumerate(list(a.accounts)[:40])]
    for e in probe:
        da = a.process(aspl.Event(e.id, e.ts, e.bo, e.type, dict(e.attrs), dict(e.tel)))
        db_ = b.process(aspl.Event(e.id, e.ts, e.bo, e.type, dict(e.attrs), dict(e.tel)))
        assert (da.action, [x["id"] for x in da.hits]) == (db_.action, [x["id"] for x in db_.hits])


def test_sweep_keeps_state_bounded():
    eng = Engine()
    eng.add_account(Account("TRADER01", "trader", 40, 0, cap_offmarket=1e12, daily_cap=1e15))
    t = 1e6
    sizes = []
    for i in range(6000):
        t += 3600
        eng.process(new_event("TRADER01", "beneficiary_add", t, {"target_bo": f"T{i:07d}"}, {}))
        eng.process(new_event("TRADER01", "offmarket_out", t + 60, {"target_bo": f"T{i:07d}", "value": 10}, {}))
        if i % 1000 == 999:
            eng.sweep(t)
            sizes.append(eng.active.monitors.size())
    assert max(sizes) < 600 and sizes[-1] <= sizes[1] * 1.1   # flat, not growing with history


# ---------------------------------------------------------------- policy lifecycle
def test_misspelt_field_is_rejected():
    bad = 'rule X "x" on offmarket_out where tel.call_actve then hold 1h explain "x"'
    with pytest.raises(PolicyRejected) as e:
        Engine(bad)
    assert "call_actve" in str(e.value)
    with pytest.raises(PolicyRejected):
        Engine('rule X "x" on offmarket_out where once[0,1h](beneficiary_add where targt == $.target_bo) then allow explain "x"')
    with pytest.raises(PolicyRejected):
        Engine('rule X "x" on offmarket_out where graph.mule_scor($.target_bo) > 1 then allow explain "x"')


def test_shadow_policy_records_disagreement_then_promotes():
    eng = _world()
    default = eng.active.src
    loose = "\n".join(l for l in default.split("\n"))  # copy
    loose = loose.replace("then hold 24h guardian\n  explain \"You are on a call", "then allow\n  explain \"You are on a call")
    eng.deploy_shadow(loose, "D1 relaxed")
    for _, e in s_digital_arrest(eng):
        d = eng.process(e)
    assert d.shadow["version"] == eng.shadow.version
    v_before = eng.active.version
    eng.promote_shadow()
    assert eng.active.version != v_before and eng.policy_history[-1]["via"] == "promote"


# ---------------------------------------------------------------- holds and audit
def test_hold_expiry_state_machine():
    eng = Engine()
    bo = senior(eng)
    eng.add_account(Account("PLAIN001", "trader", 40, 0, cap_offmarket=1e9, daily_cap=1000))
    g = eng.process(new_event(bo, "offmarket_out", 1e6, {"target_bo": "MULE0001", "value": 5000}, dict(UNKNOWN_CALL)))
    p = eng.process(new_event("PLAIN001", "offmarket_out", 1e6, {"target_bo": "FRND0001", "value": 5000}, {}))   # B5 daily cap
    assert eng.holds[g.hold_id].guardian and not eng.holds[p.hold_id].guardian
    eng.process(new_event("PLAIN001", "session_start", 1e6 + 3 * DAY, {}, {}))          # clock moves past both expiries
    assert eng.holds[g.hold_id].status == "escalated"      # guardian holds never auto-release
    assert eng.holds[p.hold_id].status == "released" and eng.graph.inflows.get("FRND0001")
    assert eng.act_on_hold(p.hold_id, "cancel") is None    # no transition out of released
    assert eng.act_on_hold(g.hold_id, "dp_confirm").status == "released"


def test_signed_checkpoints_catch_a_full_chain_rewrite():
    eng = Engine()
    bo = senior(eng)
    for i in range(30):
        eng.process(new_event(bo, "session_start", 1e6 + i, {}, {}))
    eng.audit.checkpoint()
    assert eng.audit.verify()["ok"]
    eng.audit.tamper(10, recompute=True)                   # insider rewrites every later hash
    v = eng.audit.verify()
    assert not v["ok"] and "checkpoint" in v["reason"]


# ---------------------------------------------------------------- API
@pytest.fixture(scope="module")
def client():
    from backend.main import app
    return TestClient(app)


KEY = {"X-API-Key": "dev-key"}


def ev(eid, **kw):
    body = {"event_id": eid, "ts": 1_790_000_000, "bo": "1208ASHA0072", "type": "offmarket_out",
            "attrs": {"target_bo": "1208MULE0001", "value": 1840000, "reason": "gift", "channel": "app"},
            "tel": {"call_active": True, "caller_h": "a1b2c3d4e5f60718", "call_secs": 1800}}
    body.update(kw)
    return body


def test_api_auth_and_roles(client):
    assert client.post("/v1/events", json=ev("api-1")).status_code == 401
    assert client.post("/v1/events", json=ev("api-1"), headers={"X-API-Key": "nope"}).status_code == 401
    import hashlib
    api_v1.KEYS[hashlib.sha256(b"ro-key").hexdigest()] = ("readonly", {"analyst"})
    assert client.post("/v1/events", json=ev("api-1"), headers={"X-API-Key": "ro-key"}).status_code == 403


def test_api_schema_validation(client):
    bad_attr = ev("api-2", attrs={"target_bo": "1208MULE0001", "value": 5, "colour": "red"})
    assert client.post("/v1/events", json=bad_attr, headers=KEY).status_code == 422
    missing = ev("api-3", attrs={"value": 5})
    assert client.post("/v1/events", json=missing, headers=KEY).status_code == 422
    neg = ev("api-4", attrs={"target_bo": "1208MULE0001", "value": -5})
    assert client.post("/v1/events", json=neg, headers=KEY).status_code == 422
    raw_number = ev("api-5", tel={"caller_number": "9876543210"})   # raw numbers are not accepted, only hashes
    assert client.post("/v1/events", json=raw_number, headers=KEY).status_code == 422


def test_api_decision_idempotency_and_hindi(client):
    r = client.post("/v1/events?lang=hi", json=ev("api-6"), headers=KEY)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["action"] == "hold" and "D1" in body["rules"]
    assert any("कॉल" in m["explain"] for m in body["investor_message"])
    r2 = client.post("/v1/events", json=ev("api-6"), headers=KEY)
    assert r2.headers.get("Idempotent-Replay") == "true" and r2.json()["audit"] == body["audit"]
    hid = body["hold_id"]
    ok = client.post(f"/v1/holds/{hid}/actions", json={"action": "cancel", "actor": "investor"}, headers=KEY)
    assert ok.status_code == 200 and ok.json()["status"] == "cancelled"
    again = client.post(f"/v1/holds/{hid}/actions", json={"action": "cancel", "actor": "investor"}, headers=KEY)
    assert again.status_code == 409


def test_api_policy_lint_and_ops(client):
    r = client.post("/v1/policy/lint", json={"source": 'rule X "x" on offmarket_out where tel.nope then allow'}, headers=KEY)
    assert r.status_code == 200 and not r.json()["ok"]
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").json()["ready"]
    m = client.get("/metrics").text
    assert "agentsnap_events_total" in m and "agentsnap_decision_latency_us_bucket" in m
    assert "BEGIN PUBLIC KEY" in client.get("/v1/audit/public-key").text


def test_console_api_refuses_remote_clients():
    from backend.main import app
    remote = TestClient(app, client=("203.0.113.9", 5555))
    assert remote.get("/api/ops").status_code == 403
    assert remote.get("/healthz").status_code == 200
