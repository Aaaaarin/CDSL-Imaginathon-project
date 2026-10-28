"""AgentSnap decision pipeline.

For each depository event:
  0. idempotency (a retried event returns its original decision) and per-account
     ordering (a late event is processed at the account's latest time, and flagged)
  1. telemetry enrichment (device, network, telecom) with provenance and degraded modes
  2. fold the event into the temporal monitors (active policy, and shadow if deployed)
  3. evaluate the rules bound to this event type
  4. combine hits: block > hold > step_up > allow; longest hold wins; guardian if any rule asks
  5. settle effects (graph edges, receiver credit) only if the event is allowed
  6. append to the input log and the hash-chained audit log

Failure policy: if evaluation raises, value-moving events are held (fail closed)
and everything else is allowed (fail open), and the error is counted and audited.
"""
from __future__ import annotations

import hashlib
import heapq
import json
import logging
import pickle
import time
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from . import aspl
from .audit import AuditLog, EventLog
from .domain import Account, Decision, EVENT_TYPES, LOCAL_CHECK, VALUE_EVENTS
from .graph import BOGraph
from .telemetry import TEL_FIELDS, Telemetry

POLICY_DIR = Path(__file__).resolve().parent.parent / "policies"
log = logging.getLogger("agentsnap")

ACCOUNT_FIELDS = set(Account("x", "x", 0, 0).view())
GRAPH_FUNCS = set(BOGraph().funcs())
EVENT_ATTRS = {k: v[1] for k, v in EVENT_TYPES.items()}

# hold state machine: state -> {action: next state}
HOLD_FSM = {
    "pending": {"cancel": "cancelled", "guardian_decline": "guardian_declined", "guardian_approve": "released",
                "release": "released", "expire": "released", "expire_guardian": "escalated"},
    "escalated": {"dp_confirm": "released", "cancel": "cancelled", "guardian_decline": "guardian_declined",
                  "guardian_approve": "released", "release": "released"},
}


class PolicyRejected(aspl.ASPLError):
    def __init__(self, issues):
        first = issues[0]
        super().__init__(f"{first['rule']}: {first['msg']}", first.get("line", 0), 0)
        self.issues = issues


def lint_policy(rules):
    return aspl.lint(rules, EVENT_ATTRS, TEL_FIELDS, ACCOUNT_FIELDS, GRAPH_FUNCS)


def compile_policy(src: str, strict=True):
    rules = aspl.parse_policy(src)
    issues = lint_policy(rules)
    if strict and any(i["level"] == "error" for i in issues):
        raise PolicyRejected([i for i in issues if i["level"] == "error"])
    return rules, issues


def policy_version(src: str) -> str:
    return hashlib.sha256(src.encode()).hexdigest()[:12]


@dataclass
class HoldCase:
    id: str
    decision: Decision
    event: aspl.Event
    created: float
    expires: float
    guardian: bool
    status: str = "pending"
    history: list = field(default_factory=list)

    def to_dict(self):
        return {"id": self.id, "status": self.status, "created": self.created, "expires": self.expires,
                "guardian": self.guardian, "decision": self.decision.to_dict(),
                "event": {"id": self.event.id, "type": self.event.type, "bo": self.event.bo, "attrs": self.event.attrs},
                "history": self.history}


class Metrics:
    BUCKETS = (10, 20, 50, 100, 200, 500, 1000, 5000, float("inf"))

    def __init__(self):
        self.c = defaultdict(int)
        self.rule_hits = defaultdict(int)
        self.lat = [0] * len(self.BUCKETS)
        self.lat_sum = 0.0

    def observe_latency(self, us):
        self.lat_sum += us
        for i, b in enumerate(self.BUCKETS):
            if us <= b:
                self.lat[i] += 1
                break

    def prometheus(self, gauges: dict) -> str:
        out = ["# TYPE agentsnap_events_total counter"]
        for k, v in sorted(self.c.items()):
            out.append(f'agentsnap_events_total{{kind="{k}"}} {v}')
        out.append("# TYPE agentsnap_rule_hits_total counter")
        for k, v in sorted(self.rule_hits.items()):
            out.append(f'agentsnap_rule_hits_total{{rule="{k}"}} {v}')
        out.append("# TYPE agentsnap_decision_latency_us histogram")
        acc = 0
        for b, n in zip(self.BUCKETS, self.lat):
            acc += n
            out.append(f'agentsnap_decision_latency_us_bucket{{le="{"+Inf" if b == float("inf") else b}"}} {acc}')
        out.append(f"agentsnap_decision_latency_us_sum {round(self.lat_sum, 1)}")
        out.append(f"agentsnap_decision_latency_us_count {acc}")
        typed = set()
        for k, v in gauges.items():
            base = k.split("{")[0]
            if base not in typed:
                typed.add(base)
                out.append(f"# TYPE agentsnap_{base} gauge")
            out.append(f"agentsnap_{k} {v}")
        return "\n".join(out) + "\n"

    def quantile(self, q):
        total = sum(self.lat)
        if not total:
            return 0
        acc = 0
        for b, n in zip(self.BUCKETS, self.lat):
            acc += n
            if acc >= q * total:
                return b
        return self.BUCKETS[-2]


class _PolicySet:
    """A compiled policy with its own monitors (active or shadow)."""

    def __init__(self, src, reference=False, strict=True, note=""):
        self.rules, self.issues = compile_policy(src, strict)
        self.src = src
        self.version = policy_version(src)
        self.note = note
        self.by_type = aspl.index_rules(self.rules)
        self.monitors = aspl.ReferenceMonitors() if reference else aspl.Monitors(self.rules)
        self.since = time.time()


class Engine:
    SWEEP_EVERY = 20000
    SEEN_CAP = 200000

    def __init__(self, policy_src: str | None = None, audit_path=":memory:", reference=False, listeners=None,
                 signing_key=None, strict=True):
        self.accounts: dict[str, Account] = {}
        self.telemetry = Telemetry()
        self.graph = BOGraph()
        self.audit = AuditLog(audit_path, signing_key)
        self.events = EventLog(self.audit.db, self.audit.lock)
        self.holds: dict[str, HoldCase] = {}
        self._hold_heap: list = []
        self.listeners = listeners if listeners is not None else []
        self.reference = reference
        self.stats = defaultdict(int)
        self.metrics = Metrics()
        self.seen: OrderedDict = OrderedDict()   # event id -> Decision
        self.last_ts: dict[str, float] = {}
        self.shadow: _PolicySet | None = None
        self.policy_history: list[dict] = []
        self._replaying = False
        self.load_policy(policy_src or (POLICY_DIR / "default.aspl").read_text(encoding="utf8"), note="initial", strict=strict)

    # ------------------------------------------------------------------ policy lifecycle
    @property
    def rules(self):
        return self.active.rules

    @property
    def policy_src(self):
        return self.active.src

    def load_policy(self, src: str, note="", strict=True):
        """Replace the active policy immediately. Monitors start cold; prefer
        deploy_shadow() then promote() so the new policy starts with warm state."""
        self.active = _PolicySet(src, self.reference, strict, note)
        self.policy_history.append({"version": self.active.version, "note": note, "at": time.time(), "via": "load"})
        return self.active.rules

    def deploy_shadow(self, src: str, note=""):
        self.shadow = _PolicySet(src, self.reference, True, note)
        self.stats["shadow_disagree"] = 0
        self.stats["shadow_events"] = 0
        return self.shadow

    def promote_shadow(self):
        if not self.shadow:
            raise ValueError("no shadow policy deployed")
        self.active, self.shadow = self.shadow, None
        self.policy_history.append({"version": self.active.version, "note": self.active.note, "at": time.time(), "via": "promote"})
        self.audit.append({"ts": self.graph.now, "bo": "-", "action": "policy_promote", "version": self.active.version})
        return self.active

    def discard_shadow(self):
        self.shadow = None

    # ------------------------------------------------------------------ accounts
    def add_account(self, a: Account):
        self.accounts[a.bo] = a
        self.graph.open_account(a.bo, a.opened_ts)

    def account(self, bo) -> Account:
        a = self.accounts.get(bo)
        if a is None:  # counterparty at the other depository or unseen: minimal record
            a = Account(bo=bo, persona="external", age_years=40, opened_ts=0)
            self.add_account(a)
        return a

    # ------------------------------------------------------------------ main path
    def process(self, e: aspl.Event, settle=True, derived=False) -> Decision:
        cached = self.seen.get(e.id)
        if cached is not None:
            self.metrics.c["duplicate"] += 1
            return cached
        t0 = time.perf_counter_ns()
        if not derived and not self._replaying:
            self.events.append("event", {"id": e.id, "ts": e.ts, "bo": e.bo, "type": e.type, "attrs": e.attrs, "tel": e.tel})
        flags = []
        last = self.last_ts.get(e.bo)
        if last is not None and e.ts < last:
            flags.append(f"late by {round(last - e.ts, 1)}s, processed at account time")
            e.ts = last
            self.metrics.c["late"] += 1
        self.last_ts[e.bo] = e.ts
        self._expire_holds(e.ts)

        prov, hits, shadow_action = [], [], None
        try:
            acct = self.account(e.bo)
            prov = self.telemetry.enrich(e, acct)
            g = self.graph
            g.now = max(g.now, e.ts)
            g.touch(e.bo, e.ts)
            g.bind_device(e.bo, e.tel.get("device_id"))
            view = acct.view()
            funcs = g.funcs()
            self.active.monitors.observe(e, view, funcs)
            hits = aspl.evaluate_rules(self.active.by_type, e, view, funcs, self.active.monitors)
            if self.shadow:
                self.shadow.monitors.observe(e, view, funcs)
                sh = aspl.evaluate_rules(self.shadow.by_type, e, view, funcs, self.shadow.monitors)
                shadow_action = _combine([h.rule for h in sh])[0]
            action, hold, guardian = _combine([h.rule for h in hits])
            out_hits = [_hit_dict(h) for h in hits]
            # A hold is a pause at the authorisation step, before any instruction exists,
            # under the investor's consent. Without consent, challenge and warn instead.
            if action == "hold" and not acct.cooling_consent:
                action, hold, guardian = "step_up", 0.0, False
                flags.append("no cooling consent: challenged and warned instead of paused")
        except Exception as ex:  # fail safe, never fail silent
            log.exception("evaluation failed for %s", e.id)
            self.metrics.c["engine_error"] += 1
            fail_closed = e.type in VALUE_EVENTS
            action, hold, guardian = ("hold", 4 * 3600, True) if fail_closed else ("allow", 0.0, False)
            out_hits = [{"id": "SYS", "name": "Engine error, failing safe", "action": "hold 4h guardian" if fail_closed else "allow",
                         "explain": "AgentSnap could not evaluate this request, so it is paused for review." if fail_closed else "",
                         "lesson": "", "tags": ["system"], "evidence": {"error": type(ex).__name__}, "i18n": {}}]
        lat = (time.perf_counter_ns() - t0) / 1000.0

        d = Decision(e.id, e.bo, e.type, e.ts, action, hold, guardian, out_hits, lat, LOCAL_CHECK.get(e.type, "n/a"))
        d.telemetry = prov  # type: ignore[attr-defined]
        d.flags = flags + [f"degraded: {x}" for x in e.tel.get("degraded", [])]  # type: ignore[attr-defined]
        d.policy = self.active.version  # type: ignore[attr-defined]
        if self.shadow:
            d.shadow = {"version": self.shadow.version, "action": shadow_action}  # type: ignore[attr-defined]
            self.stats["shadow_events"] += 1
            if shadow_action != action:
                self.stats["shadow_disagree"] += 1
        rec = {"ts": e.ts, "bo": e.bo, "event_id": e.id, "etype": e.type, "action": action,
               "rules": [h["id"] for h in out_hits], "hold_secs": hold, "policy": self.active.version}
        if not self._replaying:
            d.seq, d.hash = self.audit.append(rec)
        self.stats[action] += 1
        self.stats["events"] += 1
        self.metrics.c[action] += 1
        self.metrics.observe_latency(lat)
        for h in out_hits:
            self.metrics.rule_hits[h["id"]] += 1

        if action == "hold":
            hc = HoldCase(f"H-{e.id}", d, e, e.ts, e.ts + hold, guardian)
            self.holds[hc.id] = hc
            heapq.heappush(self._hold_heap, (hc.expires, hc.id))
            d.hold_id = hc.id  # type: ignore[attr-defined]
        if settle and action in ("allow", "step_up"):
            self._settle(e)
        if settle and e.type == "offmarket_in":  # credit arriving from outside this engine's view
            self.graph.transfer(e.attrs.get("source_bo"), e.bo, e.attrs.get("value", 0), e.ts)

        self.seen[e.id] = d
        if len(self.seen) > self.SEEN_CAP:
            self.seen.popitem(last=False)
        if self.stats["events"] % 1000 == 0:      # incremental: bounded work per call
            self.active.monitors.sweep(e.ts, budget=2000) if hasattr(self.active.monitors, "sweep") else None
        if self.stats["events"] % self.SWEEP_EVERY == 0:
            self.graph.sweep(e.ts)
        if not self._replaying:
            for fn in self.listeners:
                fn(d, e)
        return d

    def _settle(self, e: aspl.Event):
        if e.type == "offmarket_out":
            tgt = e.attrs.get("target_bo")
            self.graph.transfer(e.bo, tgt, e.attrs.get("value", 0), e.ts)
            credit = aspl.Event(f"{e.id}-in", e.ts, tgt, "offmarket_in", {"source_bo": e.bo, "value": e.attrs.get("value", 0)}, {})
            self.process(credit, settle=False, derived=True)

    # ------------------------------------------------------------------ holds
    def act_on_hold(self, hid: str, act: str, who: str = "investor"):
        hc = self.holds.get(hid)
        if not hc:
            return None
        nxt = HOLD_FSM.get(hc.status, {}).get(act)
        if nxt is None:
            return None
        if not self._replaying:
            self.events.append("hold", {"id": hid, "act": act, "who": who})
        hc.status = nxt
        if act == "guardian_decline":
            tgt = hc.event.attrs.get("target_bo")
            if tgt:
                self.graph.flag(tgt)  # a declined transfer marks the receiver for the graph
        if nxt == "released":
            self._settle(hc.event)
        hc.history.append({"act": act, "by": who, "status": nxt})
        if not self._replaying:
            self.audit.append({"ts": hc.event.ts, "bo": hc.event.bo, "action": f"hold_{nxt}", "hold": hid, "by": who})
        self.metrics.c[f"hold_{nxt}"] += 1
        return hc

    def _expire_holds(self, now):
        """Cooling periods end on the event clock. A plain hold releases; a guardian
        hold with no answer escalates to the DP for a call instead of releasing."""
        heap = self._hold_heap
        while heap and heap[0][0] <= now:
            _, hid = heapq.heappop(heap)
            hc = self.holds.get(hid)
            if hc and hc.status == "pending":
                self.act_on_hold(hid, "expire_guardian" if hc.guardian else "expire", "clock")

    # ------------------------------------------------------------------ housekeeping
    def sweep(self, now):
        removed = self.active.monitors.sweep(now) if hasattr(self.active.monitors, "sweep") else 0
        if self.shadow and hasattr(self.shadow.monitors, "sweep"):
            removed += self.shadow.monitors.sweep(now)
        removed += self.graph.sweep(now)
        self.metrics.c["state_swept"] += removed
        return removed

    def gauges(self):
        m = self.active.monitors
        return {"accounts": len(self.accounts), "monitor_entries": m.size() if hasattr(m, "size") else 0,
                "holds_pending": sum(1 for h in self.holds.values() if h.status == "pending"),
                "holds_escalated": sum(1 for h in self.holds.values() if h.status == "escalated"),
                "audit_seq": self.audit.seq, "event_log_seq": self.events.seq,
                "shadow_disagree": self.stats.get("shadow_disagree", 0)}

    # ------------------------------------------------------------------ snapshot and recovery
    def snapshot(self, path: str) -> dict:
        """Write all engine state to `path`. Production would use a state store
        (RocksDB, Kafka Streams); the contract is the same: state + log position."""
        self.events.flush()
        self.audit.checkpoint()
        state = {
            "policy_version": self.active.version, "policy_src": self.active.src,
            "monitors": self.active.monitors.state if hasattr(self.active.monitors, "state") else None,
            "accounts": self.accounts, "graph": self.graph, "telemetry": self.telemetry,
            "holds": self.holds, "hold_heap": self._hold_heap, "last_ts": self.last_ts,
            "seen": list(self.seen.items())[-50000:], "stats": dict(self.stats), "event_seq": self.events.seq,
        }
        blob = pickle.dumps(state, protocol=pickle.HIGHEST_PROTOCOL)
        Path(path).write_bytes(blob)
        return {"path": str(path), "bytes": len(blob), "event_seq": self.events.seq, "policy": self.active.version}

    def restore(self, path: str) -> dict:
        """Load a snapshot, then replay every logged input after it."""
        state = pickle.loads(Path(path).read_bytes())
        if state["policy_version"] != self.active.version:
            self.load_policy(state["policy_src"], note="restored")
        self.active.monitors.state = state["monitors"]
        self.accounts, self.graph, self.telemetry = state["accounts"], state["graph"], state["telemetry"]
        self.holds, self._hold_heap, self.last_ts = state["holds"], state["hold_heap"], state["last_ts"]
        self.stats = defaultdict(int, state["stats"])
        self.seen = OrderedDict(state["seen"])
        replayed = self.replay(state["event_seq"])
        return {"restored_from_seq": state["event_seq"], "replayed": replayed}

    def replay(self, after_seq: int) -> int:
        self._replaying = True
        n = 0
        try:
            for _, kind, p in self.events.after(after_seq):
                if kind == "event":
                    if p["id"] in self.seen:
                        self.seen.pop(p["id"])  # it was logged but not reflected in the snapshot
                    self.process(aspl.Event(p["id"], p["ts"], p["bo"], p["type"], p["attrs"], p["tel"]))
                elif kind == "hold":
                    self.act_on_hold(p["id"], p["act"], p["who"])
                n += 1
        finally:
            self._replaying = False
        return n


def _combine(rules):
    action, hold, guardian = "allow", 0.0, False
    for r in rules:
        if aspl.ACTION_RANK[r.action.kind] > aspl.ACTION_RANK[action]:
            action = r.action.kind
        if r.action.kind == "hold":
            hold = max(hold, r.action.hold_secs)
            guardian = guardian or r.action.guardian
    if action == "block":
        hold, guardian = 0.0, False
    return action, hold, guardian


def _hit_dict(hit):
    r = hit.rule
    return {"id": r.id, "name": r.name, "action": r.action.text(), "explain": r.explain, "lesson": r.lesson,
            "tags": r.tags, "evidence": _clean(hit.trace), "i18n": r.i18n}


def _clean(trace: dict) -> dict:
    out = {}
    for k, v in trace.items():
        if isinstance(v, float):
            v = round(v, 3)
        elif isinstance(v, frozenset):
            v = sorted(v)
        out[k] = v
    return out


def new_event(bo, etype, ts, attrs=None, tel=None, eid=None) -> aspl.Event:
    if eid is None:
        new_event.n += 1
        eid = f"e{new_event.n:010d}"
    return aspl.Event(eid, ts, bo, etype, attrs or {}, tel or {})


new_event.n = 0
