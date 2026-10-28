"""Telemetry: device, network and telecom signals attached to each event.

Three tiers, each with a different privacy treatment:

  device   computed on the phone by the AgentSnap SDK inside myEasi / broker apps.
           Only booleans and z-scores leave the device (call active, screen shared,
           remote-access app present, hesitation). No audio, no screen content.
  network  derived server-side from the session: ASN class, geo, velocity since the
           last session. The IP is truncated to /24 after enrichment.
  telecom  India-specific feeds queried by keyed hash of the number:
             TRAI 1600-series registry (BFSI service calls must come from 1600xx)
             DoT Financial Fraud Risk Indicator (medium / high / very high)
             DoT Mobile Number Revocation List
             CAMARA SIM Swap and Number Verification APIs (Airtel, Jio, Vi via
             GSMA Open Gateway)

The providers here are local stand-ins with the same request and response shape
as the real interfaces, seeded with synthetic data.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import math
import time
from dataclasses import dataclass, field

KEY = b"agentsnap-demo-hmac-key"  # production: per-deployment key held in an HSM


def h(value: str) -> str:
    """Keyed hash used for every phone number and device identifier."""
    return hmac.new(KEY, value.encode(), hashlib.sha256).hexdigest()[:16]


# ----------------------------------------------------------------- signal catalogue
SIGNALS = [
    # name, tier, source, privacy
    ("call_active", "device", "TelephonyCallback (Android) / CXCallObserver (iOS)", "boolean only"),
    ("caller_class", "telecom", "1600 registry + DoT FRI + MNRL + on-device contacts flag", "caller number hashed on device"),
    ("call_secs", "device", "call state duration", "integer"),
    ("screen_share", "device", "MediaProjection active / display mirroring", "boolean only"),
    ("remote_access_app", "device", "package scan for known remote-control apps", "boolean only"),
    ("accessibility_overlay", "device", "enabled accessibility services with overlay permission", "boolean only"),
    ("hesitation_z", "device", "touch and dwell timing vs the investor's own baseline", "z-score, baseline kept on device"),
    ("paste_beneficiary", "device", "beneficiary BO pasted from clipboard", "boolean only"),
    ("device_age_h", "device", "hours since this device was bound to the BO", "integer"),
    ("attested", "device", "Play Integrity / App Attest verdict", "boolean only"),
    ("ip_class", "network", "ASN class: mobile, residential, hosting, vpn, tor", "IP truncated to /24 after lookup"),
    ("geo_velocity_kmh", "network", "distance from last session / elapsed time", "city-level only"),
    ("sim_swap_age_h", "telecom", "CAMARA SIM Swap retrieve-date", "query by keyed hash"),
    ("number_verified", "telecom", "CAMARA Number Verification: SIM in device = registered mobile", "boolean only"),
]


# Every field the enrichment step can produce; the policy checker rejects anything else.
TEL_FIELDS = {
    "call_active", "call_secs", "screen_share", "remote_access_app", "accessibility_overlay", "hesitation_z",
    "paste_beneficiary", "device_age_h", "attested", "device_id", "caller_class", "sim_swap_age_h",
    "number_verified", "ip_class", "asn", "geo_city", "geo_velocity_kmh", "ip_24", "degraded",
}


class ProviderDown(Exception):
    pass


class Breaker:
    """Circuit breaker per provider: after `threshold` consecutive failures, stop
    calling for `cooldown` seconds and use the degraded default."""

    def __init__(self, name, threshold=3, cooldown=30.0):
        self.name, self.threshold, self.cooldown = name, threshold, cooldown
        self.fails = 0
        self.open_until = 0.0
        self.calls = self.errors = self.skipped = 0

    def call(self, fn, default):
        now = time.monotonic()
        if self.open_until > now:
            self.skipped += 1
            return default, False
        self.calls += 1
        try:
            v = fn()
            self.fails = 0
            return v, True
        except Exception:
            self.errors += 1
            self.fails += 1
            if self.fails >= self.threshold:
                self.open_until = now + self.cooldown
            return default, False

    def status(self):
        return {"name": self.name, "state": "open" if self.open_until > time.monotonic() else "closed",
                "calls": self.calls, "errors": self.errors, "skipped": self.skipped}


# ----------------------------------------------------------------- telecom providers
class CallerRegistry:
    """Classifies the caller on an active call. The 1600 registry, FRI and MNRL are
    bulk feeds synced to a local store, so lookups do not leave the depository."""

    def __init__(self):
        self.bfsi_1600: set[str] = set()    # hashes of registered 1600xx numbers
        self.fri: dict[str, str] = {}       # hash -> medium | high | very_high
        self.mnrl: set[str] = set()
        self.down = False                   # fault injection for tests and drills

    def classify(self, caller_h: str | None, in_contacts: bool) -> str:
        if self.down:
            raise ProviderDown("caller registry")
        if not caller_h:
            return "none"
        if caller_h in self.mnrl:
            return "mnrl"
        lvl = self.fri.get(caller_h)
        if lvl:
            return f"fri_{lvl}"
        if caller_h in self.bfsi_1600:
            return "bfsi_1600"
        if in_contacts:
            return "contact"
        return "unknown"

    def number_risk(self, number_h: str) -> tuple[str, bool]:
        return self.fri.get(number_h, "none"), number_h in self.mnrl


class SimSwapAPI:
    """CAMARA SIM Swap: POST /sim-swap/v0/retrieve-date {phoneNumber} -> {latestSimChange}."""

    def __init__(self):
        self.last_change: dict[str, float] = {}
        self.down = False

    def retrieve_date(self, number_h: str) -> float | None:
        if self.down:
            raise ProviderDown("sim swap")
        return self.last_change.get(number_h)

    def check(self, number_h: str, now: float, max_age_h: float) -> bool:
        t = self.last_change.get(number_h)
        return t is not None and now - t <= max_age_h * 3600


class NumberVerificationAPI:
    """CAMARA Number Verification: does the SIM in this device carry the registered number?"""

    down = False

    def verify(self, device_sim_h: str | None, registered_h: str) -> bool:
        if self.down:
            raise ProviderDown("number verification")
        return bool(device_sim_h) and device_sim_h == registered_h


# ----------------------------------------------------------------- network
@dataclass
class AsnEntry:
    net: ipaddress.IPv4Network
    asn: int
    org: str
    cls: str
    city: str
    lat: float
    lon: float


CITIES = {
    "Mumbai": (19.07, 72.88), "Pune": (18.52, 73.86), "Delhi": (28.61, 77.21),
    "Bengaluru": (12.97, 77.59), "Kolkata": (22.57, 88.36), "Chennai": (13.08, 80.27),
    "Jaipur": (26.91, 75.79), "Lucknow": (26.85, 80.95), "Phnom Penh": (11.56, 104.92),
}

# Synthetic ASN table. Ranges are illustrative, not real allocations.
ASN_TABLE = [
    AsnEntry(ipaddress.ip_network("100.64.0.0/12"), 64601, "Demo Mobile A", "mobile", "Mumbai", *CITIES["Mumbai"]),
    AsnEntry(ipaddress.ip_network("100.80.0.0/12"), 64602, "Demo Mobile B", "mobile", "Delhi", *CITIES["Delhi"]),
    AsnEntry(ipaddress.ip_network("100.96.0.0/12"), 64603, "Demo Mobile C", "mobile", "Bengaluru", *CITIES["Bengaluru"]),
    AsnEntry(ipaddress.ip_network("100.112.0.0/12"), 64604, "Demo Mobile D", "mobile", "Pune", *CITIES["Pune"]),
    AsnEntry(ipaddress.ip_network("198.18.0.0/16"), 64610, "Demo Fibre", "residential", "Kolkata", *CITIES["Kolkata"]),
    AsnEntry(ipaddress.ip_network("198.19.0.0/16"), 64611, "Demo Fibre 2", "residential", "Chennai", *CITIES["Chennai"]),
    AsnEntry(ipaddress.ip_network("203.0.113.0/24"), 64620, "Demo Cloud", "hosting", "Mumbai", *CITIES["Mumbai"]),
    AsnEntry(ipaddress.ip_network("192.0.2.0/24"), 64630, "Demo VPN", "vpn", "Phnom Penh", *CITIES["Phnom Penh"]),
    AsnEntry(ipaddress.ip_network("198.51.100.0/24"), 64640, "Demo Tor exit", "tor", "Phnom Penh", *CITIES["Phnom Penh"]),
]


def asn_lookup(ip: str | None) -> AsnEntry | None:
    if not ip:
        return None
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for e in ASN_TABLE:
        if a in e.net:
            return e
    return None


def haversine_km(a, b):
    (la1, lo1), (la2, lo2) = a, b
    p1, p2 = math.radians(la1), math.radians(la2)
    dp, dl = p2 - p1, math.radians(lo2 - lo1)
    x = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(x))


# ----------------------------------------------------------------- enrichment
@dataclass
class Telemetry:
    callers: CallerRegistry = field(default_factory=CallerRegistry)
    simswap: SimSwapAPI = field(default_factory=SimSwapAPI)
    numver: NumberVerificationAPI = field(default_factory=NumberVerificationAPI)
    last_loc: dict = field(default_factory=dict)   # bo -> (ts, (lat, lon))
    breakers: dict = field(default_factory=lambda: {n: Breaker(n) for n in ("caller_registry", "sim_swap", "number_verification")})
    swap_cache: dict = field(default_factory=dict)  # number hash -> (fetched_at_event_ts, value); CAMARA is a network call
    SWAP_TTL = 600.0

    def health(self):
        return [b.status() for b in self.breakers.values()]

    def __getstate__(self):  # breakers hold wall-clock timers; do not carry them across a restart
        d = dict(self.__dict__)
        d["breakers"] = {n: Breaker(n) for n in d["breakers"]}
        return d

    def enrich(self, e, account) -> list[dict]:
        """Turn the SDK envelope (e.tel, raw) into rule-ready signals, in place.
        Returns provenance rows for the decision record.

        Degraded modes, chosen per signal:
          caller registry down  -> caller_class 'unavailable' (treated as unverified: fails closed)
          SIM swap API down     -> sim_swap_age_h unknown (null: rules on it do not fire)
          number verification   -> number_verified false (fails closed: step-up)
        Every degradation is listed in tel.degraded and in the decision record."""
        raw = e.tel
        prov = []
        degraded = []
        br = self.breakers
        tel = {
            "call_active": bool(raw.get("call_active")),
            "call_secs": int(raw.get("call_secs", 0)),
            "screen_share": bool(raw.get("screen_share")),
            "remote_access_app": bool(raw.get("remote_access_app")),
            "accessibility_overlay": bool(raw.get("accessibility_overlay")),
            "hesitation_z": float(raw.get("hesitation_z", 0.0)),
            "paste_beneficiary": bool(raw.get("paste_beneficiary")),
            "device_age_h": float(raw.get("device_age_h", 9999)),
            "attested": bool(raw.get("attested", True)),
            "device_id": raw.get("device_id"),
        }
        # telecom: caller
        if tel["call_active"] or raw.get("caller_h"):
            cc, ok = br["caller_registry"].call(lambda: self.callers.classify(raw.get("caller_h"), bool(raw.get("caller_in_contacts"))), "unavailable")
            if not ok:
                degraded.append("caller_registry")
        else:
            cc = "none"
        tel["caller_class"] = cc
        if tel["call_active"]:
            prov.append({"signal": "caller_class", "value": tel["caller_class"], "source": "1600 registry, DoT FRI, MNRL"})
        # telecom: SIM swap (cached, a network call in production) and number verification
        hit = self.swap_cache.get(account.mobile_h)
        if hit and 0 <= e.ts - hit[0] < self.SWAP_TTL:
            t = hit[1]
        else:
            t, ok = br["sim_swap"].call(lambda: self.simswap.retrieve_date(account.mobile_h), "unknown")
            if ok:
                self.swap_cache[account.mobile_h] = (e.ts, t)
            else:
                degraded.append("sim_swap")
                t = None
        tel["sim_swap_age_h"] = round((e.ts - t) / 3600, 1) if t is not None and t <= e.ts else None
        if tel["sim_swap_age_h"] is not None and tel["sim_swap_age_h"] < 24 * 30:
            prov.append({"signal": "sim_swap_age_h", "value": tel["sim_swap_age_h"], "source": "CAMARA SIM Swap"})
        nv, ok = br["number_verification"].call(lambda: self.numver.verify(raw.get("device_sim_h"), account.mobile_h), False)
        if not ok:
            degraded.append("number_verification")
        tel["number_verified"] = nv
        # network
        a = asn_lookup(raw.get("ip"))
        tel["ip_class"] = a.cls if a else "unknown"
        tel["asn"] = a.asn if a else None
        tel["geo_city"] = a.city if a else None
        tel["geo_velocity_kmh"] = 0.0
        if a:
            here = (a.lat, a.lon)
            last = self.last_loc.get(e.bo)
            if last:
                dt_h = max((e.ts - last[0]) / 3600, 1 / 60)
                tel["geo_velocity_kmh"] = round(haversine_km(last[1], here) / dt_h, 1)
            self.last_loc[e.bo] = (e.ts, here)
            if tel["ip_class"] in ("hosting", "vpn", "tor") or tel["geo_velocity_kmh"] > 500:
                prov.append({"signal": "ip_class", "value": f"{tel['ip_class']} AS{a.asn} {a.city}", "source": "ASN table"})
        tel["ip_24"] = ".".join(raw.get("ip", "").split(".")[:3]) + ".0/24" if raw.get("ip") else None
        for k in ("screen_share", "remote_access_app", "accessibility_overlay"):
            if tel[k]:
                prov.append({"signal": k, "value": True, "source": "AgentSnap SDK"})
        if tel["call_active"]:
            prov.append({"signal": "call_active", "value": f"{tel['call_secs']}s", "source": "AgentSnap SDK"})
        tel["degraded"] = degraded
        for d in degraded:
            prov.append({"signal": "degraded", "value": d, "source": "provider unavailable, degraded default used"})
        e.tel = tel
        return prov
