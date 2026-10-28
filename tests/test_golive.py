"""The go-live workarounds: feed files, CAMARA client, key rotation and witness log,
consent-based pauses, the opt-in lock, privacy export, retention, hardening, and
the on-premises shadow replay."""
import json

import pytest
from fastapi.testclient import TestClient

from backend import shadow_replay
from backend.audit import load_signing_key, save_signing_key
from backend.domain import Account
from backend.engine import Engine, new_event
from backend.feeds import CamaraClient, FeedSync, mock_camara_app
from backend.telemetry import CallerRegistry, h

CALL = {"call_active": True, "caller_h": h("scammer"), "call_secs": 900}


def test_feed_sync_hashes_numbers_and_rejects_bad_files(tmp_path):
    (tmp_path / "1600.csv").write_text("number\n1600 123 456\n1600-999-000\n")
    (tmp_path / "fri.csv").write_text("number,level\n+91 98765 43210,Very High\n9123409876,high\n")
    (tmp_path / "mnrl.csv").write_text("9000000001\n")
    reg = CallerRegistry()
    rep = FeedSync(reg, tmp_path).sync()
    assert rep.ok and rep.loaded == {"1600.csv": 2, "fri.csv": 2, "mnrl.csv": 1}
    assert reg.fri[h("9876543210")] == "very_high" and h("1600123456") in reg.bfsi_1600
    assert not any("98765" in k for k in reg.fri)                 # only hashes are kept
    (tmp_path / "fri.csv").write_text("9123409876,catastrophic\n")
    rep2 = FeedSync(reg, tmp_path).sync()
    assert not rep2.ok and reg.fri[h("9876543210")] == "very_high"   # old lists stay live


def test_camara_client_speaks_the_published_shape():
    app = mock_camara_app({"+919876543210": "2026-09-14T01:10:00Z"})
    c = CamaraClient(base_url="http://mock", client_id="as", client_secret="s")
    c.http = TestClient(app, base_url="http://mock")
    nh = c.register("9876543210")
    t = c.retrieve_date(nh)
    assert t is not None and c.check(nh, t + 3600, 72) and not c.check(nh, t + 100 * 3600, 72)
    assert c.retrieve_date(h("0000000000")) is None


def test_key_rotation_and_witness_log(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTSNAP_WITNESS", str(tmp_path / "witness.jsonl"))
    key_file = tmp_path / "key.pem"
    save_signing_key(load_signing_key(), str(key_file), "correct horse")
    eng = Engine(signing_key=load_signing_key(str(key_file), "correct horse"))
    eng.add_account(Account("ACCT0001", "trader", 40, 0))
    for i in range(1200):
        eng.process(new_event("ACCT0001", "session_start", 1e6 + i, {}, {}))
    old = eng.audit.kid
    assert eng.audit.rotate_key() != old
    for i in range(1200):
        eng.process(new_event("ACCT0001", "session_start", 2e6 + i, {}, {}))
    eng.audit.checkpoint()
    v = eng.audit.verify()
    assert v["ok"] and v["signed_checkpoints"] >= 3
    lines = (tmp_path / "witness.jsonl").read_text().splitlines()
    assert len({json.loads(l)["kid"] for l in lines}) == 2
    assert eng.audit.verify_witness(lines)["ok"]
    eng.audit.tamper(500, recompute=True)                       # rewrite history in the database
    assert not eng.audit.verify_witness(lines)["ok"]            # the published copy disagrees


def test_without_consent_a_hold_becomes_a_challenge():
    eng = Engine()
    eng.add_account(Account("SEN00001", "senior", 70, 0, cap_offmarket=1000, cooling_consent=False))
    d = eng.process(new_event("SEN00001", "offmarket_out", 1e6, {"target_bo": "MULE0001", "value": 5000}, dict(CALL)))
    assert d.action == "step_up" and any("consent" in f for f in d.flags) and not eng.holds


def test_opt_in_new_beneficiary_lock():
    eng = Engine()
    eng.add_account(Account("SEN00002", "senior", 70, 0, guardian=True, lock_new_beneficiary=True))
    eng.process(new_event("SEN00002", "beneficiary_add", 1e6, {"target_bo": "NEW00001"}, {}))
    d = eng.process(new_event("SEN00002", "offmarket_out", 1e6 + 86400, {"target_bo": "NEW00001", "value": 9000}, {}))
    assert d.action == "hold" and "B6" in [x["id"] for x in d.hits]


@pytest.fixture(scope="module")
def client():
    from backend.main import app
    return TestClient(app)


def test_privacy_export_and_hardening(client):
    from backend.main import live
    bo = next(iter(live.eng.accounts))
    r = client.get(f"/v1/privacy/export/{bo}", headers={"X-API-Key": "dev-key"})
    assert r.status_code == 200 and "raw phone numbers" in r.json()["not_held"]
    page = client.get("/")
    assert page.headers["x-frame-options"] == "DENY" and "frame-ancestors 'none'" in page.headers["content-security-policy"]
    big = client.post("/v1/events", content=b"x" * 1_100_000, headers={"X-API-Key": "dev-key", "Content-Type": "application/json"})
    assert big.status_code == 413
    assert client.post("/v1/admin/retention", headers={"X-API-Key": "dev-key"}).status_code in (200, 409)


def test_shadow_replay_on_an_export(tmp_path):
    rows = [
        {"event_id": "x1", "ts": 1_790_000_000, "bo": "1208ASHA0072", "type": "beneficiary_add", "attrs": {"target_bo": "1208MULE0001"},
         "tel": {"call_active": True, "caller_h": "aa11bb22cc33dd44", "call_secs": 600}},
        {"event_id": "x2", "ts": 1_790_000_900, "bo": "1208ASHA0072", "type": "offmarket_out",
         "attrs": {"target_bo": "1208MULE0001", "value": 1840000, "reason": "gift", "channel": "app"},
         "tel": {"call_active": True, "caller_h": "aa11bb22cc33dd44", "call_secs": 1500}},
        {"event_id": "x3", "ts": 1_790_001_000, "bo": "1208PRAK0064", "type": "session_start", "attrs": {}, "tel": {}},
        {"event_id": "bad", "ts": 5, "bo": "nope", "type": "offmarket_out"},
    ]
    f = tmp_path / "export.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in rows))
    (tmp_path / "fraud.txt").write_text("1208ASHA0072\n")
    rep = shadow_replay.run(str(f), fraud_path=str(tmp_path / "fraud.txt"))
    assert rep["events"] == 3 and sum(rep["rejected"].values()) == 1
    assert rep["fraud_accounts_held"] == 1 and rep["holds_on_accounts_without_fraud"] == 0
