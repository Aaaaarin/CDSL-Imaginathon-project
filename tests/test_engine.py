"""End-to-end behaviour: kill chains, holds, telemetry, audit chain, benchmark floor."""
import pytest

from backend import bench
from backend.domain import Account
from backend.engine import Engine, new_event
from backend.scenarios import replay
from backend.telemetry import Telemetry, h, asn_lookup

EXPECT = {
    # scenario: (step where AgentSnap stops it or None, action at that step, rules that must fire there)
    "digital_arrest": (3, "hold", {"D1", "B2", "B3"}),
    "sim_swap": (2, "hold", {"T3"}),
    "remote_access": (2, "hold", {"D2", "D5"}),
    "pledge_misuse": (3, "block", {"P1"}),
    "mule_rent": (5, "hold", {"B4"}),
    "fake_kyc": (1, "block", {"T5"}),
    "callback": (None, None, set()),
    "family_gift": (None, None, set()),
}


@pytest.mark.parametrize("sid", list(EXPECT))
def test_scenarios(sid):
    r = replay(sid)
    step, action, rules = EXPECT[sid]
    assert r["stopped_at"] == step
    # every step before the stop passed today's checks and was allowed
    for s in r["steps"][: (step or len(r["steps"])) - 1]:
        assert s["decision"]["action"] in ("allow", "step_up")
    if step:
        d = r["steps"][step - 1]["decision"]
        assert d["action"] == action
        assert rules <= {x["id"] for x in d["hits"]}
        assert all(x["explain"] for x in d["hits"])


def test_family_gift_has_no_friction():
    r = replay("family_gift")
    assert [s["decision"]["action"] for s in r["steps"]] == ["allow", "allow"]


def test_sim_swap_later_steps_also_caught():
    r = replay("sim_swap")
    last = r["steps"][-1]["decision"]
    assert last["action"] == "hold" and {"T1", "T2", "T9"} <= {x["id"] for x in last["hits"]}


def test_hold_does_not_settle_until_released():
    eng = Engine()
    eng.add_account(Account("A", "senior", 70, 0, cap_offmarket=1000))
    t = {"call_active": True, "caller_h": h("x"), "call_secs": 900}
    d = eng.process(new_event("A", "offmarket_out", 10_000, {"target_bo": "M", "value": 5000}, t))
    assert d.action == "hold"
    assert eng.graph.fan_in_distinct("M") == 0          # nothing moved
    eng.act_on_hold(d.hold_id, "release")
    assert eng.graph.inflows["M"]                         # released transfer settles


def test_guardian_decline_flags_receiver():
    eng = Engine()
    eng.add_account(Account("A", "senior", 70, 0, cap_offmarket=1000))
    t = {"call_active": True, "caller_h": h("x"), "call_secs": 900}
    d = eng.process(new_event("A", "offmarket_out", 10_000, {"target_bo": "M", "value": 5000}, t))
    eng.act_on_hold(d.hold_id, "guardian_decline")
    assert eng.graph.mule_score("M") == 1.0


def test_caller_classification():
    tel = Telemetry()
    tel.callers.bfsi_1600.add(h("1600111111"))
    tel.callers.fri[h("999")] = "high"
    tel.callers.mnrl.add(h("888"))
    c = tel.callers.classify
    assert c(h("1600111111"), False) == "bfsi_1600"
    assert c(h("999"), True) == "fri_high"          # a flagged number stays flagged even if saved
    assert c(h("888"), False) == "mnrl"
    assert c(h("777"), True) == "contact"
    assert c(h("777"), False) == "unknown"
    assert c(None, False) == "none"


def test_network_enrichment_velocity():
    eng = Engine()
    eng.add_account(Account("A", "trader", 30, 0))
    eng.process(new_event("A", "session_start", 0, {}, {"ip": "100.64.1.1"}))           # Mumbai
    eng.process(new_event("A", "session_start", 1800, {}, {"ip": "192.0.2.5"}))         # VPN exit in Phnom Penh, 30 min later
    e = new_event("A", "beneficiary_add", 1900, {"target_bo": "Z"}, {"ip": "192.0.2.5"})
    d = eng.process(e)
    assert e.tel["ip_class"] == "vpn"
    assert d.action == "step_up" and "T6" in {x["id"] for x in d.hits}
    assert asn_lookup("10.0.0.1") is None


def test_audit_chain_localises_tampering():
    eng = Engine()
    eng.add_account(Account("A", "trader", 30, 0))
    for i in range(50):
        eng.process(new_event("A", "session_start", i * 10, {}, {}))
    assert eng.audit.verify()["ok"]
    eng.audit.tamper(17)
    v = eng.audit.verify()
    assert not v["ok"] and v["first_bad_seq"] == 17


def test_benchmark_floor():
    out, *_ = bench.run(accounts=1500, days=30, attacks=12, seed=3, quiet=True)
    assert out["attacks"]["stopped_pct"] >= 90
    assert out["benign"]["false_hold_pct"] <= 0.6
    assert out["attacks"]["stopped_pct"] > out["naive_threshold"]["stopped_pct"] + 30
    assert out["audit"]["ok"]
