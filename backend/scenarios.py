"""Named kill-chain replays for the console. Each runs on a fresh engine with just
enough surrounding world (mule accounts with prior inflows, telecom registries) to
make the signals real. People are fictional."""
from __future__ import annotations

from .domain import Account
from .engine import Engine, new_event
from .telemetry import h

DAY, HOUR, MIN = 86400.0, 3600.0, 60.0
T = 1_790_000_000.0  # mid-September 2026

SCAM = "9876501234"
SCAM_FRI = "9123409876"


def _world(policy=None):
    eng = Engine(policy)
    reg = eng.telemetry.callers
    reg.fri[h(SCAM_FRI)] = "very_high"
    reg.bfsi_1600.add(h("1600123456"))
    # mule M1: 9 days old, shares a phone with two other new accounts, already received from three strangers today
    for bo, age in (("1208MULE0001", 9), ("1208MULE0002", 12), ("1208MULE0003", 6)):
        eng.add_account(Account(bo, "mule", 22, T - age * DAY, label="mule"))
        eng.graph.bind_device(bo, h("mule-phone-1"))
    for i, src in enumerate(("1301XXXX0041", "1208XXXX7713", "1301XXXX5528")):
        eng.process(new_event("1208MULE0001", "offmarket_in", T - (5 - i) * HOUR, {"source_bo": src, "value": 240000 + 9000 * i}, {}))
    return eng


def tel(dev="dev-main", call=None, caller=None, contacts=False, ip="100.112.4.20", age=5000, **kw):
    t = {"device_id": h(dev), "device_age_h": age, "ip": ip, "attested": True, "device_sim_h": kw.pop("sim", h("victim-mobile"))}
    if call:
        t.update({"call_active": True, "caller_h": h(caller) if caller else None, "caller_in_contacts": contacts, "call_secs": call})
    t.update(kw)
    return t


def victim(eng, bo, persona, age, **kw):
    a = Account(bo, persona, age, T - 900 * DAY, mobile_h=h("victim-mobile"), **kw)
    eng.add_account(a)
    return a


SCENARIOS = {}


def scenario(id, title, who, summary):
    def deco(fn):
        SCENARIOS[id] = {"id": id, "title": title, "who": who, "summary": summary, "fn": fn}
        return fn
    return deco


@scenario("digital_arrest", "Digital arrest", "Asha, 72, retired teacher, Pune",
          "A caller posing as CBI keeps her on the line for an hour and walks her through moving her shares to a 'verification account'.")
def s_digital_arrest(eng):
    bo = "1208ASHA0072"
    victim(eng, bo, "senior", 72, cap_offmarket=100000, daily_cap=300000, guardian=True)
    return [
        ("The call starts. The number is not saved and not a 1600-series number.",
         new_event(bo, "session_start", T, {"channel": "app"}, tel(call=240, caller=SCAM_FRI))),
        ("She pastes a BO ID the caller sent on WhatsApp and adds it as a beneficiary. The OTP is valid.",
         new_event(bo, "beneficiary_add", T + 35 * MIN, {"target_bo": "1208MULE0001", "channel": "app"},
                   tel(call=2340, caller=SCAM_FRI, paste_beneficiary=True, hesitation_z=2.4))),
        ("Still on the call, she transfers ₹18.4 lakh of shares as a 'gift'. TPIN and OTP are valid.",
         new_event(bo, "offmarket_out", T + 52 * MIN, {"target_bo": "1208MULE0001", "value": 1840000, "reason": "gift", "channel": "app"},
                   tel(call=3360, caller=SCAM_FRI, hesitation_z=3.1))),
    ]


@scenario("sim_swap", "SIM-swap takeover", "Rohan, 29, first-time investor, Bengaluru",
          "His SIM is swapped at night. By morning someone on a new phone has changed his email and is moving his holdings.")
def s_sim_swap(eng):
    bo = "1208ROHN0029"
    a = victim(eng, bo, "first_time", 29, cap_offmarket=100000, daily_cap=200000)
    eng.telemetry.simswap.last_change[a.mobile_h] = T
    atk = dict(dev="attacker-phone", ip="203.0.113.77", sim=h("victim-mobile"))
    return [
        ("01:10 the operator reports a SIM change on his number. A new phone logs in from a data-centre IP.",
         new_event(bo, "session_start", T + 70 * MIN, {"channel": "app"}, tel(age=0.2, **atk))),
        ("The registered email is changed, so alerts stop reaching him. OTP arrives on the swapped SIM.",
         new_event(bo, "contact_change", T + 80 * MIN, {"field": "email", "channel": "app", "new_mobile_fri": "none", "new_mobile_mnrl": False}, tel(age=0.4, **atk))),
        ("A beneficiary is added from the new phone.",
         new_event(bo, "beneficiary_add", T + 95 * MIN, {"target_bo": "1208MULE0002", "channel": "app"}, tel(age=0.6, **atk))),
        ("₹1.8 lakh of shares are transferred out.",
         new_event(bo, "offmarket_out", T + 110 * MIN, {"target_bo": "1208MULE0002", "value": 180000, "reason": "transfer", "channel": "app"}, tel(age=0.8, **atk))),
    ]


@scenario("remote_access", "Fake broker support", "Meera, 58, long-term investor, Mumbai",
          "A 'support executive' asks her to install a screen-sharing app to fix a failed order, then watches her TPIN.")
def s_remote(eng):
    bo = "1208MEER0058"
    victim(eng, bo, "long_term", 58, cap_offmarket=200000, daily_cap=500000)
    rt = dict(call=600, caller=SCAM, remote_access_app=True, screen_share=True)
    return [
        ("She installs the app the caller names and starts screen sharing.",
         new_event(bo, "session_start", T, {"channel": "app"}, tel(**rt))),
        ("The caller asks her to 'test' a sale of 30% of her portfolio.",
         new_event(bo, "edis_auth", T + 6 * MIN, {"isin": "INE000DEMO03", "qty": 120, "value": 360000, "portfolio_frac": 0.3}, tel(**rt))),
        ("Then to add a 'settlement account' and move the rest there.",
         new_event(bo, "beneficiary_add", T + 12 * MIN, {"target_bo": "1208MULE0003", "channel": "app"}, tel(**rt))),
        ("Transfer of ₹6.2 lakh.",
         new_event(bo, "offmarket_out", T + 15 * MIN, {"target_bo": "1208MULE0003", "value": 620000, "reason": "transfer", "channel": "app"}, tel(**rt))),
    ]


@scenario("pledge_misuse", "Broker pledges client shares", "Vikram, 46, trader, Delhi",
          "The Karvy pattern: a broker with standing authority pledges a client's idle shares to its own lender.")
def s_pledge(eng):
    bo = "1208VIKR0046"
    victim(eng, bo, "trader", 46, cap_offmarket=500000, daily_cap=2000000)
    return [
        ("Years ago he signed DDPI so his broker can settle sales without a TPIN each time.",
         new_event(bo, "ddpi_register", T - 400 * DAY, {"tm": "TM-0001"}, tel())),
        ("A normal margin pledge to his own broker for an open position.",
         new_event(bo, "pledge_create", T - 2 * DAY, {"pledgee": "own_tm", "pledgee_id": "TM-0001", "value": 210000, "margin_need": 200000}, tel())),
        ("No open position, but ₹9 lakh of his shares are pledged to a third-party lender. DDPI is on file, so no OTP is asked.",
         new_event(bo, "pledge_create", T, {"pledgee": "third_party", "pledgee_id": "LENDER-DEMO", "value": 900000, "margin_need": 0}, tel())),
    ]


@scenario("mule_rent", "Student rents out a demat", "Kabir, 19, first-year student, Lucknow",
          "A Telegram ad offers ₹5,000 a month to 'use' his demat account. Shares stolen from four people pass through it in a day.")
def s_mule(eng):
    bo = "1208KABR0019"
    victim(eng, bo, "student", 19, cap_offmarket=50000, daily_cap=100000)
    evs = []
    for i, (src, v) in enumerate((("1301XXXX1101", 80000), ("1208XXXX2207", 65000), ("1301XXXX3319", 110000), ("1208XXXX4420", 45000))):
        evs.append((f"Shares worth ₹{v:,} arrive from an account he has never heard of.",
                    new_event(bo, "offmarket_in", T + i * 2 * HOUR, {"source_bo": src, "value": v}, {})))
    evs.append(("The 'employer' tells him to forward everything to another account.",
                new_event(bo, "offmarket_out", T + 9 * HOUR, {"target_bo": "1208MULE0001", "value": 300000, "reason": "transfer", "channel": "app"}, tel())))
    return evs


@scenario("fake_kyc", "Fake KYC update", "Suresh, 66, retired, Chennai",
          "A caller from the 'depository KYC cell' says his account will be frozen unless he updates his mobile number now.")
def s_fake_kyc(eng):
    bo = "1208SURE0066"
    victim(eng, bo, "senior", 66, cap_offmarket=100000, daily_cap=300000, guardian=True)
    lvl = eng.telemetry.callers.number_risk(h(SCAM_FRI))[0]
    return [
        ("On the call, he changes his registered mobile to the number the caller gives. DoT has flagged that number.",
         new_event(bo, "contact_change", T, {"field": "mobile", "channel": "app", "new_mobile_fri": lvl, "new_mobile_mnrl": False}, tel(call=700, caller=SCAM))),
    ]


@scenario("callback", "Known gap: the patient caller", "Lata, 70, Jaipur",
          "The scammer tells her to hang up, add the beneficiary the next day, and send an amount just under her limit. Shown to be honest about what AgentSnap misses.")
def s_callback(eng):
    bo = "1208LATA0070"
    victim(eng, bo, "senior", 70, cap_offmarket=100000, daily_cap=300000, guardian=True)
    return [
        ("Day 1, calm session, no call: she adds the beneficiary she was told about yesterday.",
         new_event(bo, "beneficiary_add", T, {"target_bo": "1208XXXX9001", "channel": "app"}, tel())),
        ("Day 2, no call active: she sends ₹95,000, just under her ₹1 lakh limit, to a 70-day-old account with no history.",
         new_event(bo, "offmarket_out", T + 22 * HOUR, {"target_bo": "1208XXXX9001", "value": 95000, "reason": "gift", "channel": "app"}, tel())),
    ]


@scenario("family_gift", "Control: a real family gift", "Prakash, 64, Kolkata",
          "On a call with his daughter, he adds her new demat account and sends her shares for her wedding. AgentSnap should stay out of the way.")
def s_family(eng):
    bo = "1208PRAK0064"
    victim(eng, bo, "senior", 64, cap_offmarket=300000, daily_cap=600000, guardian=True)
    eng.add_account(Account("1208DAUG0031", "first_time", 31, T - 500 * DAY))
    return [
        ("He is on a call with his daughter, who is saved in his contacts. He adds her BO ID.",
         new_event(bo, "beneficiary_add", T - 3 * DAY, {"target_bo": "1208DAUG0031", "channel": "app"}, tel(call=400, caller="daughter", contacts=True))),
        ("Three days later, on another call with her, he sends ₹2.5 lakh of shares.",
         new_event(bo, "offmarket_out", T, {"target_bo": "1208DAUG0031", "value": 250000, "reason": "gift", "channel": "app"}, tel(call=300, caller="daughter", contacts=True))),
    ]


def replay(sid, policy=None):
    s = SCENARIOS[sid]
    eng = _world(policy)
    steps = s["fn"](eng)
    t0 = steps[0][1].ts
    out = []
    for text, e in steps:
        raw_tel = dict(e.tel)
        d = eng.process(e)
        out.append({
            "t_offset": e.ts - t0, "text": text, "type": e.type, "attrs": e.attrs,
            "local_check": d.local_check, "decision": d.to_dict(), "telemetry": getattr(d, "telemetry", []),
            "signals": {k: v for k, v in e.tel.items() if k not in ("device_id",)},
            "raw_signal_keys": sorted(k for k in raw_tel if k not in ("caller_h", "device_sim_h", "device_id", "ip")),
        })
    final = next((st for st in out if st["decision"]["action"] in ("hold", "block")), None)
    return {"id": sid, "title": s["title"], "who": s["who"], "summary": s["summary"], "steps": out,
            "stopped_at": out.index(final) + 1 if final else None,
            "graph": eng.graph.neighbourhood(steps[-1][1].attrs.get("target_bo") or steps[-1][1].bo)}


def catalogue():
    return [{k: v for k, v in s.items() if k != "fn"} for s in SCENARIOS.values()]
