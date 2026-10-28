"""Synthetic depository world: population, everyday behaviour, and attacks.

Everything is generated from a seed so every number in the benchmark can be
reproduced. Benign behaviour deliberately includes hard negatives: family gifts
during calls with relatives, beneficiaries pasted from WhatsApp, legitimate
contact changes followed by transfers, investors who keep AnyDesk installed for
work, VPN users, travellers.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .domain import Account
from .engine import Engine, new_event
from .telemetry import h

T0 = datetime(2026, 9, 1, tzinfo=timezone.utc).timestamp()
DAY, HOUR, MIN = 86400.0, 3600.0, 60.0

CITY_MOBILE = {"Mumbai": (100, 64), "Delhi": (100, 80), "Bengaluru": (100, 96), "Pune": (100, 112)}
CITY_FIBRE = {"Kolkata": (198, 18), "Chennai": (198, 19)}
CITIES = list(CITY_MOBILE) + list(CITY_FIBRE)

PERSONAS = {
    #             share  age range   cap      daily     sessions edis  offm  pledge  mf
    "student":    (0.18, (18, 24),   50000,   100000,   8,       0.4,  0.03, 0.0,    0.1),
    "first_time": (0.30, (22, 40),   100000,  200000,   10,      1.0,  0.05, 0.0,    0.3),
    "senior":     (0.15, (60, 85),   100000,  300000,   6,       0.5,  0.20, 0.0,    0.4),
    "trader":     (0.17, (25, 55),   500000,  2000000,  40,      12.0, 0.08, 3.0,    0.2),
    "hni":        (0.08, (35, 70),   1000000, 5000000,  15,      3.0,  0.30, 2.0,    0.5),
    "long_term":  (0.12, (30, 60),   200000,  500000,   5,       0.3,  0.08, 0.0,    0.3),
}


def ip_for(rng, city, kind="home"):
    if kind == "hosting":
        return f"203.0.113.{rng.randint(1, 254)}"
    if kind == "vpn":
        return f"192.0.2.{rng.randint(1, 254)}"
    if kind == "tor":
        return f"198.51.100.{rng.randint(1, 254)}"
    if city in CITY_MOBILE:
        a, b = CITY_MOBILE[city]
        return f"{a}.{b + rng.randint(0, 15)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    a, b = CITY_FIBRE[city]
    return f"{a}.{b}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


@dataclass
class Person:
    acct: Account
    mobile: str
    device: str
    city: str
    family: list[str] = field(default_factory=list)    # BOs of relatives
    beneficiaries: set = field(default_factory=set)
    portfolio: float = 0.0
    remote_app: bool = False
    vpn_user: bool = False
    has_ddpi: bool = False


@dataclass
class Incident:
    id: str
    kind: str
    variant: str
    victim: str
    events: list = field(default_factory=list)        # all events of the chain
    theft: list = field(default_factory=list)         # event ids that complete the loss
    value: float = 0.0
    story: list = field(default_factory=list)


class World:
    """Holds the population and telecom registries; emits benign and attack events."""

    def __init__(self, engine: Engine, seed=7, optin=0.0):
        self.eng = engine
        self.rng = random.Random(seed)
        self.optin = optin   # share of seniors with a guardian who turn on the new-beneficiary lock
        self.people: dict[str, Person] = {}
        self.mules: list[str] = []
        self.dormant: list[str] = []
        self.scam_numbers: list[str] = []
        self.bfsi_numbers: list[str] = []
        self.n_bo = 0
        self._seed_telecom()

    # ------------------------------------------------------------- setup
    def _seed_telecom(self):
        reg = self.eng.telemetry.callers
        for i in range(40):
            n = f"1600{i:06d}"
            self.bfsi_numbers.append(n)
            reg.bfsi_1600.add(h(n))
        for i in range(300):
            n = f"9{self.rng.randint(100000000, 999999999)}"
            self.scam_numbers.append(n)
            r = self.rng.random()
            if r < 0.35:   # numbers already reported: DoT FRI or revoked
                reg.fri[h(n)] = self.rng.choice(["medium", "high", "very_high"])
            elif r < 0.45:
                reg.mnrl.add(h(n))

    def new_bo(self):
        self.n_bo += 1
        return f"12081600{self.n_bo:08d}"

    def make_person(self, persona, opened_ts=None) -> Person:
        rng = self.rng
        share, (amin, amax), cap, daily, *_ = PERSONAS[persona]
        bo = self.new_bo()
        mobile = f"{rng.choice('6789')}{rng.randint(100000000, 999999999)}"
        acct = Account(bo, persona, rng.randint(amin, amax), opened_ts if opened_ts is not None else T0 - rng.uniform(60, 3000) * DAY,
                       cap_offmarket=cap, daily_cap=daily, guardian=persona == "senior" and rng.random() < 0.7,
                       mobile_h=h(mobile), home_city=rng.choice(CITIES))
        p = Person(acct, mobile, h(f"dev-{bo}"), acct.home_city,
                   portfolio=rng.lognormvariate(12.5 if persona != "hni" else 15.5, 0.9),
                   remote_app=rng.random() < 0.02, vpn_user=rng.random() < 0.03,
                   has_ddpi=persona in ("trader", "hni") or rng.random() < 0.3)
        if self.optin and persona == "senior" and acct.guardian:
            acct.lock_new_beneficiary = self.rng.random() < self.optin
        self.people[bo] = p
        self.eng.add_account(acct)
        return p

    def populate(self, n):
        names = list(PERSONAS)
        weights = [PERSONAS[k][0] for k in names]
        for _ in range(n):
            self.make_person(self.rng.choices(names, weights)[0])
        bos = list(self.people)
        # India opened 2.7 crore demat accounts in FY26: many families have a member
        # whose account is weeks old (a grandchild's first demat). 12% of people do.
        newcomers = []
        for _ in range(max(1, n // 12)):
            newcomers.append(self.make_person("first_time", opened_ts=T0 - self.rng.uniform(5, 110) * DAY).acct.bo)
        for bo in bos:  # family links for gifts
            p = self.people[bo]
            p.family = self.rng.sample(bos, k=self.rng.randint(1, 3))
            p.family = [f for f in p.family if f != bo]
            if self.rng.random() < 0.12:
                p.family.append(self.rng.choice(newcomers))
            p.beneficiaries = set(self.rng.sample(p.family, k=min(len(p.family), self.rng.randint(0, 2))))

    def make_mules(self, n):
        """Mule BOs. Half are fresh accounts, half are older accounts bought or rented
        from real people. About a third are run in rings of three from one phone."""
        rng = self.rng
        for i in range(n):
            fresh = rng.random() < 0.5
            age = rng.uniform(2, 25) if fresh else rng.uniform(60, 900)
            p = self.make_person("student", opened_ts=T0 - age * DAY)
            p.acct.label = "mule"
            if rng.random() < 0.35:
                p.device = h(f"mulephone-{i // 3}")
            self.mules.append(p.acct.bo)
            self.eng.graph.bind_device(p.acct.bo, p.device)

    # ------------------------------------------------------------- telemetry helpers
    def tel(self, p: Person, *, call=None, caller=None, in_contacts=False, ip_kind="home", city=None,
            device=None, device_age_h=None, screen=False, remote=None, paste=False, hes=0.0, sim=True):
        rng = self.rng
        t = {"device_id": device or p.device, "device_age_h": device_age_h if device_age_h is not None else rng.uniform(200, 20000),
             "ip": ip_for(rng, city or p.city, ip_kind), "attested": True,
             "device_sim_h": h(p.mobile) if sim else h("other-sim"), "hesitation_z": hes,
             "screen_share": screen, "remote_access_app": p.remote_app if remote is None else remote,
             "paste_beneficiary": paste}
        if call:
            t.update({"call_active": True, "caller_h": h(caller) if caller else None,
                      "caller_in_contacts": in_contacts, "call_secs": int(call)})
        return t

    def benign_call(self, p):
        """Most sessions have no call; some are on a call with family, a broker, or someone unsaved."""
        r = self.rng.random()
        if r < 0.90:
            return {}
        r = self.rng.random()
        if r < 0.70:
            return {"call": self.rng.randint(30, 1200), "caller": "fam-" + p.acct.bo, "in_contacts": True}
        if r < 0.85:
            return {"call": self.rng.randint(30, 600), "caller": self.rng.choice(self.bfsi_numbers)}
        return {"call": self.rng.randint(30, 900), "caller": f"8{self.rng.randint(100000000, 999999999)}"}

    def benign_ip(self, p):
        if p.vpn_user and self.rng.random() < 0.5:
            return {"ip_kind": "vpn"}
        if self.rng.random() < 0.03:
            return {"city": self.rng.choice(CITIES)}  # travel
        return {}

    # ------------------------------------------------------------- benign month
    def benign_events(self, days):
        """Yield (ts, Event) for everyday activity over `days`, unsorted."""
        rng = self.rng
        out = []
        for bo, p in list(self.people.items()):
            if p.acct.label == "mule":
                continue
            share, ages, cap, daily, sess, edis, offm, pledge, mf = PERSONAS[p.acct.persona]
            scale = days / 30
            # dormant accounts: 4% of long-term and senior investors do nothing at all
            if p.acct.persona in ("long_term", "senior") and rng.random() < 0.04:
                self.dormant.append(bo)
                continue
            for _ in range(_pois(rng, sess * scale)):
                ts = T0 + rng.uniform(0, days * DAY)
                out.append(new_event(bo, "session_start", ts, {"channel": "app"}, self.tel(p, **self.benign_ip(p))))
            for _ in range(_pois(rng, edis * scale)):
                ts = T0 + rng.uniform(0, days * DAY)
                frac = min(rng.betavariate(1.2, 12), 0.95)
                v = round(p.portfolio * frac)
                if p.has_ddpi:
                    out.append(new_event(bo, "sale_settle", ts, {"value": v, "via": "ddpi"}, self.tel(p)))
                else:
                    c = self.benign_call(p)
                    out.append(new_event(bo, "edis_auth", ts, {"isin": "INE000DEMO01", "qty": 10, "value": v, "portfolio_frac": round(frac, 3)},
                                         self.tel(p, **c, **self.benign_ip(p))))
            for _ in range(_pois(rng, offm * scale)):
                ts = T0 + rng.uniform(1 * DAY, days * DAY)
                if not p.family:
                    continue
                tgt = rng.choice(p.family)
                v = round(min(p.portfolio * rng.uniform(0.02, 0.4), p.acct.cap_offmarket * rng.uniform(0.2, 1.6)))
                c = self.benign_call(p)
                if tgt not in p.beneficiaries:
                    gap = rng.choice([rng.uniform(5 * MIN, 2 * HOUR), rng.uniform(1 * DAY, 10 * DAY)])
                    paste = rng.random() < 0.4  # BO ids are often copied from a family WhatsApp message
                    out.append(new_event(bo, "beneficiary_add", ts - gap, {"target_bo": tgt, "channel": "app"},
                                         self.tel(p, paste=paste, **self.benign_ip(p))))
                    p.beneficiaries.add(tgt)
                out.append(new_event(bo, "offmarket_out", ts, {"target_bo": tgt, "value": v, "reason": "gift", "channel": "app"},
                                     self.tel(p, **c)))
            for _ in range(_pois(rng, pledge * scale)):
                ts = T0 + rng.uniform(0, days * DAY)
                need = round(p.portfolio * rng.uniform(0.05, 0.3))
                out.append(new_event(bo, "pledge_create", ts, {"pledgee": "own_tm", "pledgee_id": p.acct.own_tm,
                                                               "value": round(need * rng.uniform(0.9, 1.2)), "margin_need": need}, self.tel(p)))
            for _ in range(_pois(rng, mf * scale)):
                ts = T0 + rng.uniform(0, days * DAY)
                out.append(new_event(bo, "mf_redeem", ts, {"value": round(p.portfolio * rng.uniform(0.02, 0.2)), "bank": "registered"}, self.tel(p)))
            # legitimate SIM replacement (lost or upgraded phone): 0.8% a month. The operator
            # reports a SIM change and a new device is bound; a fifth then move shares within 10 days.
            if rng.random() < 0.008 * scale:
                ts = T0 + rng.uniform(0, days * DAY)
                self.eng.telemetry.simswap.last_change[p.acct.mobile_h] = ts
                nd = h(f"newphone-{bo}")
                out.append(new_event(bo, "session_start", ts + rng.uniform(1, 30) * HOUR, {"channel": "app"}, self.tel(p, device=nd, device_age_h=1)))
                if rng.random() < 0.2 and p.family:
                    tgt = rng.choice(sorted(p.beneficiaries) or p.family)
                    lag = rng.uniform(1, 10) * DAY
                    out.append(new_event(bo, "offmarket_out", ts + lag, {"target_bo": tgt, "value": round(p.acct.cap_offmarket * rng.uniform(0.1, 0.9)),
                                                                        "reason": "family", "channel": "app"}, self.tel(p, device=nd, device_age_h=lag / HOUR)))
            # contact changes: 2% a month, a third at a DP branch; some followed by a transfer within 3 days
            if rng.random() < 0.02 * scale:
                ts = T0 + rng.uniform(0, days * DAY)
                fld = rng.choice(["mobile", "email", "email", "bank"])
                ch = "dp_branch" if rng.random() < 0.33 else "app"
                out.append(new_event(bo, "contact_change", ts, {"field": fld, "channel": ch, "new_mobile_fri": "none", "new_mobile_mnrl": False}, self.tel(p)))
                if rng.random() < 0.15 and p.family:
                    tgt = rng.choice(sorted(p.beneficiaries) or p.family)
                    out.append(new_event(bo, "offmarket_out", ts + rng.uniform(4 * HOUR, 6 * DAY),
                                         {"target_bo": tgt, "value": round(p.acct.cap_offmarket * rng.uniform(0.1, 0.8)), "reason": "family", "channel": "app"}, self.tel(p)))
                if fld == "bank" and rng.random() < 0.3:
                    out.append(new_event(bo, "mf_redeem", ts + rng.uniform(1 * DAY, 10 * DAY), {"value": round(p.portfolio * 0.1), "bank": "changed"}, self.tel(p)))
        return out

    # ------------------------------------------------------------- attacks
    def attack(self, kind, ts, variant=None) -> Incident | None:
        fn = getattr(self, f"_atk_{ATTACK_FN.get(kind, kind)}")
        return fn(ts, variant)

    def _victim(self, personas):
        pool = [p for p in self.people.values() if p.acct.persona in personas and p.acct.label == "benign"]
        return self.rng.choice(pool) if pool else None

    def _scam_caller(self):
        return self.rng.choice(self.scam_numbers)

    def _inc(self, kind, variant, p):
        return Incident(f"{kind}-{self.rng.randint(0, 10**9):09d}", kind, variant, p.acct.bo)

    def _atk_digital_arrest(self, ts, variant):
        rng = self.rng
        p = self._victim(["senior"])
        variant = variant or rng.choices(["classic", "liquidation", "callback"], [0.55, 0.3, 0.15])[0]
        inc = self._inc("digital_arrest", variant, p)
        caller = self._scam_caller()
        mule = rng.choice(self.mules)
        call0 = rng.randint(600, 3600)
        ev = inc.events
        ev.append(new_event(p.acct.bo, "session_start", ts, {"channel": "app"}, self.tel(p, call=call0, caller=caller)))
        if variant == "liquidation":
            for k in range(rng.randint(1, 3)):
                frac = rng.uniform(0.25, 0.6)
                v = round(p.portfolio * frac)
                e = new_event(p.acct.bo, "edis_auth", ts + (k + 1) * rng.uniform(5, 20) * MIN,
                              {"isin": "INE000DEMO02", "qty": 100, "value": v, "portfolio_frac": round(frac, 3)},
                              self.tel(p, call=call0 + 600 * (k + 1), caller=caller, hes=rng.uniform(1, 3)))
                ev.append(e); inc.theft.append(e.id); inc.value += v
            return inc
        v = round(p.portfolio * rng.uniform(0.3, 0.9))
        if variant == "classic":
            ev.append(new_event(p.acct.bo, "beneficiary_add", ts + rng.uniform(10, 40) * MIN, {"target_bo": mule, "channel": "app"},
                                self.tel(p, call=call0 + 1200, caller=caller, paste=True, hes=rng.uniform(1, 3))))
            e = new_event(p.acct.bo, "offmarket_out", ts + rng.uniform(45, 90) * MIN, {"target_bo": mule, "value": v, "reason": "gift", "channel": "app"},
                          self.tel(p, call=call0 + 2400, caller=caller, hes=rng.uniform(1.5, 3.5)))
        else:  # callback: scammer has the victim hang up, add the beneficiary the day before, keep the amount small
            v = round(min(v, p.acct.cap_offmarket * 0.9))
            ev.append(new_event(p.acct.bo, "beneficiary_add", ts - rng.uniform(16, 30) * HOUR, {"target_bo": mule, "channel": "app"}, self.tel(p)))
            e = new_event(p.acct.bo, "offmarket_out", ts + rng.uniform(1, 3) * HOUR, {"target_bo": mule, "value": v, "reason": "gift", "channel": "app"}, self.tel(p))
        ev.append(e); inc.theft.append(e.id); inc.value = v
        return inc

    def _atk_sim_swap(self, ts, variant):
        rng = self.rng
        p = self._victim(["first_time", "trader", "long_term", "hni"])
        variant = variant or rng.choices(["fast", "slow"], [0.8, 0.2])[0]
        inc = self._inc("sim_swap", variant, p)
        self.eng.telemetry.simswap.last_change[p.acct.mobile_h] = ts
        dev = h(f"atk-dev-{inc.id}")
        mule = rng.choice(self.mules)
        delay = rng.uniform(1, 6) * HOUR if variant == "fast" else rng.uniform(4, 6) * DAY
        kind = rng.choice(["hosting", "vpn", "home"])
        T = ts + delay
        ev = inc.events
        ev.append(new_event(p.acct.bo, "session_start", T, {"channel": "app"}, self.tel(p, device=dev, device_age_h=0.2, ip_kind=kind)))
        if variant == "fast":
            ev.append(new_event(p.acct.bo, "contact_change", T + 10 * MIN, {"field": "email", "channel": "app", "new_mobile_fri": "none", "new_mobile_mnrl": False},
                                self.tel(p, device=dev, device_age_h=0.4, ip_kind=kind)))
        ev.append(new_event(p.acct.bo, "beneficiary_add", T + 25 * MIN, {"target_bo": mule, "channel": "app"},
                            self.tel(p, device=dev, device_age_h=0.6 if variant == "fast" else 100, ip_kind=kind)))
        v = round(min(p.portfolio * rng.uniform(0.3, 0.9), p.acct.daily_cap * 0.9))
        e = new_event(p.acct.bo, "offmarket_out", T + 40 * MIN, {"target_bo": mule, "value": v, "reason": "transfer", "channel": "app"},
                      self.tel(p, device=dev, device_age_h=0.8 if variant == "fast" else 100, ip_kind=kind))
        ev.append(e); inc.theft.append(e.id); inc.value = v
        return inc

    def _atk_remote_access(self, ts, variant):
        rng = self.rng
        p = self._victim(["senior", "first_time", "long_term"])
        inc = self._inc("remote_access", variant or "fake_support", p)
        caller = self._scam_caller()
        mule = rng.choice(self.mules)
        ev = inc.events
        ev.append(new_event(p.acct.bo, "session_start", ts, {"channel": "app"}, self.tel(p, call=300, caller=caller, remote=True, screen=True)))
        ev.append(new_event(p.acct.bo, "beneficiary_add", ts + 8 * MIN, {"target_bo": mule, "channel": "app"},
                            self.tel(p, call=800, caller=caller, remote=True, screen=True)))
        v = round(p.portfolio * rng.uniform(0.2, 0.7))
        e = new_event(p.acct.bo, "offmarket_out", ts + 15 * MIN, {"target_bo": mule, "value": v, "reason": "transfer", "channel": "app"},
                      self.tel(p, call=1200, caller=caller, remote=True, screen=True))
        ev.append(e); inc.theft.append(e.id); inc.value = v
        return inc

    def _atk_pledge_misuse(self, ts, variant):
        rng = self.rng
        p = self._victim(["trader", "hni"])
        variant = variant or rng.choice(["third_party", "excess"])
        inc = self._inc("pledge_misuse", variant, p)
        v = round(p.portfolio * rng.uniform(0.4, 0.9))
        if variant == "third_party":
            a = {"pledgee": "third_party", "pledgee_id": "LENDER-DEMO", "value": v, "margin_need": 0}
        else:
            a = {"pledgee": "own_tm", "pledgee_id": p.acct.own_tm, "value": v, "margin_need": round(v * rng.uniform(0.05, 0.3))}
        e = new_event(p.acct.bo, "pledge_create", ts, a, self.tel(p))  # broker-initiated: investor's device context is idle
        inc.events.append(e); inc.theft.append(e.id); inc.value = v
        return inc

    def _atk_mule_rent(self, ts, variant):
        """A real student account rented out: shares from several victims pass through it."""
        rng = self.rng
        p = self._victim(["student"])
        variant = variant or rng.choices(["burst", "slow"], [0.75, 0.25])[0]
        inc = self._inc("mule_rent", variant, p)
        agg = rng.choice(self.mules)
        n = rng.randint(3, 5)
        spread = 10 * HOUR if variant == "burst" else 4 * DAY
        total = 0
        for i in range(n):
            src = self.new_bo()  # victims elsewhere, e.g. at the other depository
            v = rng.randint(20000, 120000)
            total += v
            inc.events.append(new_event(p.acct.bo, "offmarket_in", ts + i * spread / n, {"source_bo": src, "value": v}, {}))
        e = new_event(p.acct.bo, "offmarket_out", ts + spread + rng.uniform(1, 4) * HOUR, {"target_bo": agg, "value": total, "reason": "transfer", "channel": "app"},
                      self.tel(p))
        inc.events.append(e); inc.theft.append(e.id); inc.value = total
        return inc

    def _atk_fake_kyc(self, ts, variant):
        rng = self.rng
        p = self._victim(["senior", "first_time", "long_term"])
        inc = self._inc("fake_kyc", variant or "mobile_swap", p)
        caller = self._scam_caller()
        new_mobile = self._scam_caller()
        reg = self.eng.telemetry.callers
        lvl, mnrl = reg.number_risk(h(new_mobile))
        e1 = new_event(p.acct.bo, "contact_change", ts, {"field": "mobile", "channel": "app", "new_mobile_fri": lvl, "new_mobile_mnrl": mnrl},
                       self.tel(p, call=900, caller=caller))
        mule = rng.choice(self.mules)
        dev = h(f"atk-dev-{inc.id}")
        e2 = new_event(p.acct.bo, "beneficiary_add", ts + rng.uniform(2, 20) * HOUR, {"target_bo": mule, "channel": "app"},
                       self.tel(p, device=dev, device_age_h=1, sim=False))
        v = round(p.portfolio * rng.uniform(0.3, 0.8))
        e3 = new_event(p.acct.bo, "offmarket_out", e2.ts + 30 * MIN, {"target_bo": mule, "value": v, "reason": "transfer", "channel": "app"},
                       self.tel(p, device=dev, device_age_h=1.5, sim=False))
        inc.events += [e1, e2, e3]; inc.theft += [e1.id, e3.id]; inc.value = v
        return inc

    def _atk_dormant(self, ts, variant):
        rng = self.rng
        pool = [self.people[b] for b in self.dormant] or [p for p in self.people.values() if p.acct.persona == "long_term"]
        p = rng.choice(pool)
        inc = self._inc("dormant_takeover", variant or "credential_theft", p)
        dev = h(f"atk-dev-{inc.id}")
        mule = rng.choice(self.mules)
        kind = rng.choice(["vpn", "hosting"])
        inc.events.append(new_event(p.acct.bo, "beneficiary_add", ts, {"target_bo": mule, "channel": "app"}, self.tel(p, device=dev, device_age_h=0.5, ip_kind=kind)))
        v = round(max(p.portfolio * rng.uniform(0.4, 0.9), 210000))
        e = new_event(p.acct.bo, "offmarket_out", ts + 2 * HOUR, {"target_bo": mule, "value": v, "reason": "transfer", "channel": "app"},
                      self.tel(p, device=dev, device_age_h=2.5, ip_kind=kind))
        inc.events.append(e); inc.theft.append(e.id); inc.value = v
        return inc


ATTACK_KINDS = ["digital_arrest", "sim_swap", "remote_access", "pledge_misuse", "mule_rent", "fake_kyc", "dormant_takeover"]
ATTACK_FN = {k: ("dormant" if k == "dormant_takeover" else k) for k in ATTACK_KINDS}


def _pois(rng, lam):
    # Knuth for small lambda, normal approximation above 30
    if lam <= 0:
        return 0
    if lam > 30:
        return max(0, int(rng.gauss(lam, lam ** 0.5) + 0.5))
    import math
    L, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= L:
            return k
        k += 1
