"""BO graph: who sends securities to whom, and which accounts share devices.

A depository sees both legs of every off-market transfer, so it can see patterns no
single broker or bank can: an account that receives from many unrelated BOs and
forwards everything on, or a cluster of new accounts operated from one phone.

Mule score follows the patterns RBIH's MuleHunter work describes for bank accounts
(dormant then active, many credits then one large debit), adapted to demat:

    z = -4.2 + 0.9*min(fan_in_24h, 6) + 2.2*passthrough + 1.4*[age < 30d]
          + 0.8*min(device_cluster-1, 4) + 1.6*dormant_reactivated + 2.5*neighbour_flagged
    mule_score = sigmoid(z)

Weights are hand-set and documented; production would fit them on labelled cases.
"""
from __future__ import annotations

import math
from collections import defaultdict, deque

DAY = 86400.0


class BOGraph:
    def __init__(self):
        self.inflows: dict[str, deque] = defaultdict(deque)    # bo -> (ts, src, value)
        self.outflows: dict[str, deque] = defaultdict(deque)   # bo -> (ts, dst, value)
        self.device_bos: dict[str, set] = defaultdict(set)
        self.bo_devices: dict[str, set] = defaultdict(set)
        self.opened: dict[str, float] = {}
        self.last_active: dict[str, float] = {}
        self.prev_active: dict[str, float] = {}
        self.flagged: set[str] = set()
        self.now = 0.0

    # --------------------------------------------------------------- updates
    def open_account(self, bo, ts):
        self.opened[bo] = ts

    def bind_device(self, bo, device_id):
        if device_id:
            self.device_bos[device_id].add(bo)
            self.bo_devices[bo].add(device_id)

    def touch(self, bo, ts):
        self.now = max(self.now, ts)
        last = self.last_active.get(bo)
        if last is not None and ts - last > 3600:
            self.prev_active[bo] = last
        self.last_active[bo] = ts

    def transfer(self, src, dst, value, ts):
        self.now = max(self.now, ts)
        self.outflows[src].append((ts, dst, value))
        self.inflows[dst].append((ts, src, value))
        for q in (self.outflows[src], self.inflows[dst]):
            while q and q[0][0] < ts - 30 * DAY:
                q.popleft()

    def flag(self, bo):
        self.flagged.add(bo)

    def sweep(self, now) -> int:
        """Drop transfer history older than 30 days and empty entries."""
        removed = 0
        for d in (self.inflows, self.outflows):
            for bo in list(d):
                q = d[bo]
                while q and q[0][0] < now - 30 * DAY:
                    q.popleft(); removed += 1
                if not q:
                    del d[bo]
        return removed

    # --------------------------------------------------------------- features
    def fan_in_distinct(self, bo, window=DAY):
        t0 = self.now - window
        return len({s for ts, s, _ in self.inflows.get(bo, ()) if ts >= t0})

    def passthrough(self, bo, window=2 * DAY):
        t0 = self.now - window
        vin = sum(v for ts, _, v in self.inflows.get(bo, ()) if ts >= t0)
        vout = sum(v for ts, _, v in self.outflows.get(bo, ()) if ts >= t0)
        return min(vout / vin, 1.0) if vin else 0.0

    def age_days(self, bo):
        o = self.opened.get(bo)
        return round((self.now - o) / DAY, 1) if o is not None else 9999.0

    def device_cluster(self, bo):
        return max((len(self.device_bos[d]) for d in self.bo_devices.get(bo, ())), default=1)

    def dormant_reactivated(self, bo):
        p, l = self.prev_active.get(bo), self.last_active.get(bo)
        return bool(p is not None and l is not None and l - p > 180 * DAY and self.now - l < 7 * DAY)

    def neighbour_flagged(self, bo):
        for d in self.bo_devices.get(bo, ()):
            if any(x in self.flagged for x in self.device_bos[d] if x != bo):
                return True
        return False

    def features(self, bo):
        return {
            "fan_in_24h": self.fan_in_distinct(bo),
            "passthrough": round(self.passthrough(bo), 2),
            "age_days": self.age_days(bo),
            "device_cluster": self.device_cluster(bo),
            "dormant_reactivated": self.dormant_reactivated(bo),
            "neighbour_flagged": self.neighbour_flagged(bo),
            "flagged": bo in self.flagged,
        }

    def mule_score(self, bo):
        if bo in self.flagged:
            return 1.0
        f = self.features(bo)
        z = (-4.2 + 0.9 * min(f["fan_in_24h"], 6) + 2.2 * f["passthrough"]
             + 1.4 * (f["age_days"] < 30) + 0.8 * min(f["device_cluster"] - 1, 4)
             + 1.6 * f["dormant_reactivated"] + 2.5 * f["neighbour_flagged"])
        return round(1 / (1 + math.exp(-z)), 3)

    def funcs(self):
        """Functions exposed to ASPL as graph.*"""
        return {
            "graph.mule_score": self.mule_score,
            "graph.fan_in_distinct": lambda bo: self.fan_in_distinct(bo),
            "graph.age_days": self.age_days,
            "graph.device_cluster": self.device_cluster,
            "graph.passthrough": self.passthrough,
        }

    def neighbourhood(self, bo, depth=2, limit=60):
        """Nodes and edges around a BO for the console graph view."""
        nodes, edges, frontier = {bo}, [], {bo}
        for _ in range(depth):
            nxt = set()
            for n in frontier:
                for ts, d, v in self.outflows.get(n, ()):
                    edges.append({"src": n, "dst": d, "value": v, "ts": ts, "kind": "transfer"})
                    nxt.add(d)
                for ts, s, v in self.inflows.get(n, ()):
                    edges.append({"src": s, "dst": n, "value": v, "ts": ts, "kind": "transfer"})
                    nxt.add(s)
                for dev in self.bo_devices.get(n, ()):
                    for o in self.device_bos[dev]:
                        if o != n:
                            edges.append({"src": n, "dst": o, "kind": "device", "device": dev[:6]})
                            nxt.add(o)
            nxt -= nodes
            nodes |= set(list(nxt)[: max(0, limit - len(nodes))])
            frontier = nxt
        uniq, seen = [], set()
        for e in edges:
            k = (e["src"], e["dst"], e["kind"], e.get("ts"))
            if k not in seen and e["src"] in nodes and e["dst"] in nodes:
                seen.add(k)
                uniq.append(e)
        return {"nodes": [{"bo": n, "mule_score": self.mule_score(n), **self.features(n)} for n in nodes], "edges": uniq}
