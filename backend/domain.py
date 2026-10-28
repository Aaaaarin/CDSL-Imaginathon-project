"""Depository domain model: BO accounts and the events that change them.

Event types mirror what a depository actually records for a beneficial owner (BO)
account. Attributes are the subset the policy needs; identifiers are synthetic.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Event type -> (description, attributes)
EVENT_TYPES: dict[str, tuple[str, list[str]]] = {
    "session_start":   ("Investor opens the depository or broker app", ["channel"]),
    "contact_change":  ("Registered mobile, email, bank or address modified", ["field", "channel", "new_mobile_fri", "new_mobile_mnrl"]),
    "beneficiary_add": ("Counterparty BO added to the off-market beneficiary list (CDSL, Dec 2023)", ["target_bo", "channel"]),
    "ddpi_register":   ("Demat Debit and Pledge Instruction registered for a broker", ["tm"]),
    "ddpi_revoke":     ("DDPI revoked", ["tm"]),
    "edis_auth":       ("Sale authorised through eDIS with TPIN and OTP", ["isin", "qty", "value", "portfolio_frac"]),
    "sale_settle":     ("Exchange sale settled from the BO account", ["value", "via"]),
    "offmarket_out":   ("Off-market transfer debit to another BO", ["target_bo", "value", "reason", "channel"]),
    "offmarket_in":    ("Off-market transfer credit from another BO", ["source_bo", "value"]),
    "pledge_create":   ("Margin pledge or loan pledge created", ["pledgee", "pledgee_id", "value", "margin_need"]),
    "mf_redeem":       ("Mutual fund units redeemed", ["value", "bank"]),
    "freeze":          ("Investor freezes the BO account", []),
    "unfreeze":        ("Investor unfreezes the BO account", []),
}

# Events that move value out of the investor's control. "Today's check" for these is
# the authentication step only (OTP, TPIN, DDPI on file).
VALUE_EVENTS = {"offmarket_out", "edis_auth", "pledge_create", "mf_redeem"}

LOCAL_CHECK = {
    "contact_change": "OTP to registered contact",
    "beneficiary_add": "OTP valid",
    "ddpi_register": "eSign valid",
    "edis_auth": "TPIN + OTP valid",
    "offmarket_out": "TPIN + OTP valid",
    "pledge_create": "DDPI on file",
    "mf_redeem": "OTP valid",
    "sale_settle": "settlement",
    "offmarket_in": "credit",
    "session_start": "login OTP",
}


@dataclass
class Account:
    bo: str
    persona: str                  # student | first_time | senior | trader | hni | mule
    age_years: int
    opened_ts: float
    cap_offmarket: float = 200000  # single transfer above this needs a calm context
    daily_cap: float = 500000
    guardian: bool = False         # a trusted contact is registered
    own_tm: str = "TM-0001"
    lock_offmarket: bool = False   # investor-set safety lock
    lock_pledge: bool = False
    lock_new_beneficiary: bool = False  # investor-set: pause transfers to accounts added this week
    cooling_consent: bool = True       # investor agreed to pre-authorisation pauses (see docs/GO_LIVE.md)
    mobile_h: str = ""             # keyed hash of the registered mobile
    home_city: str = "Mumbai"
    label: str = "benign"          # simulator ground truth, never read by rules

    def view(self) -> dict:
        """What rules can read as account.*"""
        return {
            "bo": self.bo, "persona": self.persona, "age_years": self.age_years,
            "cap_offmarket": self.cap_offmarket, "daily_cap": self.daily_cap,
            "guardian": self.guardian, "own_tm": self.own_tm,
            "lock_offmarket": self.lock_offmarket, "lock_pledge": self.lock_pledge,
            "lock_new_beneficiary": self.lock_new_beneficiary,
            "senior": self.age_years >= 60,
        }


@dataclass
class Decision:
    event_id: str
    bo: str
    etype: str
    ts: float
    action: str                    # allow | step_up | hold | block
    hold_secs: float = 0
    guardian: bool = False
    hits: list = field(default_factory=list)   # [{id, name, action, explain, lesson, tags, evidence}]
    latency_us: float = 0.0
    local_check: str = ""
    seq: int = 0
    hash: str = ""

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id, "bo": self.bo, "etype": self.etype, "ts": self.ts,
            "action": self.action, "hold_secs": self.hold_secs, "guardian": self.guardian,
            "hits": self.hits, "latency_us": round(self.latency_us, 1),
            "local_check": self.local_check, "seq": self.seq, "hash": self.hash,
            "flags": getattr(self, "flags", []), "policy": getattr(self, "policy", None),
            "shadow": getattr(self, "shadow", None), "hold_id": getattr(self, "hold_id", None),
        }
