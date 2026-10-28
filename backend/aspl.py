"""ASPL: the AgentSnap Policy Language.

A rule fires on one event type and tests a condition over the current event, its
telemetry, the account, the BO graph, and the account's past. Past-time operators
(once/never/count/distinct/sum over a window, and since) form a fragment of
past-time metric temporal logic with counting.

Two evaluators share one AST:
  * incremental: each temporal node keeps per-account monitor state that is
    updated as events arrive. A node whose condition only correlates with the
    current event through `field == $.attr` is sliced by that key, so a query is a
    dictionary lookup plus a window prune.
  * reference: scans the full account history. Slow, obviously correct, and used
    by the differential tests to check the incremental monitors.

    rule R3 "Fresh beneficiary then transfer"
      on offmarket_out
      where once[0, 2h](beneficiary_add where target_bo == $.target_bo)
      then hold 24h guardian
"""
from __future__ import annotations

import re
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

# --------------------------------------------------------------------------- lexer

UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
KEYWORDS = {
    "rule", "on", "where", "then", "explain", "lesson", "tags", "and", "or", "not", "in",
    "true", "false", "allow", "step_up", "hold", "block", "guardian",
    "once", "never", "count", "distinct", "sum", "since", "null",
}
TOKEN_RE = re.compile(r"""
    (?P<ws>\s+|\#[^\n]*)
  | (?P<dur>\d+(?:\.\d+)?(?:s|m|h|d)\b)
  | (?P<num>\d[\d_]*(?:\.\d+)?)
  | (?P<str>"(?:[^"\\]|\\.)*")
  | (?P<op>==|!=|<=|>=|[<>+\-*/(){}\[\],.$;])
  | (?P<name>[A-Za-z_][A-Za-z0-9_]*)
""", re.X)


class ASPLError(Exception):
    def __init__(self, msg: str, line: int = 0, col: int = 0):
        super().__init__(f"line {line}, col {col}: {msg}" if line else msg)
        self.line, self.col = line, col


@dataclass
class Tok:
    kind: str
    val: Any
    line: int
    col: int


def lex(src: str) -> list[Tok]:
    out, pos, line, lstart = [], 0, 1, 0
    while pos < len(src):
        m = TOKEN_RE.match(src, pos)
        if not m:
            raise ASPLError(f"unexpected character {src[pos]!r}", line, pos - lstart + 1)
        kind, text = m.lastgroup, m.group()
        col = pos - lstart + 1
        if kind == "ws":
            nl = text.count("\n")
            if nl:
                line += nl
                lstart = pos + text.rfind("\n") + 1
        elif kind == "dur":
            out.append(Tok("dur", float(text[:-1]) * UNITS[text[-1]], line, col))
        elif kind == "num":
            v = text.replace("_", "")
            out.append(Tok("num", float(v) if "." in v else int(v), line, col))
        elif kind == "str":
            # only \" \\ \n \t are escapes; everything else (Hindi, ₹) passes through untouched
            body = re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t"}.get(m.group(1), m.group(1)), text[1:-1])
            out.append(Tok("str", body, line, col))
        elif kind == "name":
            out.append(Tok("kw" if text in KEYWORDS else "name", text, line, col))
        else:
            out.append(Tok("op", text, line, col))
        pos = m.end()
    out.append(Tok("eof", None, line, pos - lstart + 1))
    return out

# --------------------------------------------------------------------------- AST


class Node:
    def ev(self, c: "Ctx") -> Any: raise NotImplementedError
    def refs_current(self) -> bool:
        return any(ch.refs_current() for ch in self.children())
    def children(self) -> list["Node"]: return []
    def walk(self):
        yield self
        for ch in self.children():
            yield from ch.walk()


@dataclass
class Lit(Node):
    v: Any
    def ev(self, c): return self.v


@dataclass
class SetLit(Node):
    items: list
    def ev(self, c): return frozenset(self.items)


@dataclass
class Path(Node):
    """root: 'cur' ($), 'ev' (bare name: the event in scope), 'tel', 'account'."""
    root: str
    parts: list[str]

    def ev(self, c):
        v = self._resolve(c)
        if c.scope_event is c.current and self.root != "cur":
            c.touch_value(self.text(), v)
        return v

    def _resolve(self, c):
        if self.root == "account":
            obj = c.account
        elif self.root == "tel":
            obj = c.scope_event.tel if c.scope_event is not None else {}
        elif self.root == "cur":
            obj = c.current.attrs
        else:  # bare name: attrs of the event in scope (past event inside a temporal)
            obj = c.scope_event.attrs if c.scope_event is not None else {}
        for p in self.parts:
            obj = obj.get(p) if isinstance(obj, dict) else getattr(obj, p, None)
            if obj is None:
                return None
        return obj

    def refs_current(self):
        return self.root == "cur"

    def text(self):
        head = {"cur": "$", "ev": "", "tel": "tel", "account": "account"}[self.root]
        return ".".join([head] + self.parts if head else self.parts)


@dataclass
class Unary(Node):
    op: str
    a: Node
    def children(self): return [self.a]
    def ev(self, c):
        v = self.a.ev(c)
        if self.op == "not":
            return not truthy(v)
        return None if v is None else -v


@dataclass
class Bin(Node):
    op: str
    a: Node
    b: Node
    def children(self): return [self.a, self.b]

    def ev(self, c):
        op = self.op
        if op == "and":
            return truthy(self.a.ev(c)) and truthy(self.b.ev(c))
        if op == "or":
            return truthy(self.a.ev(c)) or truthy(self.b.ev(c))
        x, y = self.a.ev(c), self.b.ev(c)
        if op == "==": return x == y
        if op == "!=": return x != y
        if op in ("in", "not in"):
            r = x in y if isinstance(y, (frozenset, set, list, tuple, str)) else False
            return r if op == "in" else not r
        if x is None or y is None:
            return False if op in ("<", "<=", ">", ">=") else None
        if op == "<": return x < y
        if op == "<=": return x <= y
        if op == ">": return x > y
        if op == ">=": return x >= y
        if op == "+": return x + y
        if op == "-": return x - y
        if op == "*": return x * y
        if op == "/": return x / y if y else None
        raise ASPLError(f"bad operator {op}")


@dataclass
class Call(Node):
    ns: str
    fn: str
    args: list[Node]
    def children(self): return list(self.args)

    def ev(self, c):
        f = c.funcs.get(f"{self.ns}.{self.fn}")
        if f is None:
            raise ASPLError(f"unknown function {self.ns}.{self.fn}")
        vals = [a.ev(c) for a in self.args]
        out = f(*vals)
        c.touch_value(f"{self.ns}.{self.fn}({', '.join(map(str, vals))})", out)
        return out


_node_ids = iter(range(1, 10**9))


@dataclass
class Temporal(Node):
    """op in once|never|count|distinct|sum over events of `etype` in [now-hi, now-lo]."""
    op: str
    lo: float
    hi: float
    etype: str
    fld: str | None
    cond: Node | None
    nid: int = field(default_factory=lambda: next(_node_ids))
    # compiled: slice key (past attr == current expr) and residual condition
    slice_field: str | None = None
    slice_cur: Node | None = None
    residual: Node | None = None
    buffered: bool = False

    def children(self): return [self.cond] if self.cond else []

    def refs_current(self):
        # the node's value depends on the current event only through the slice key
        # or (in buffered mode) the residual condition
        return self.slice_cur is not None or self.buffered

    def ev(self, c):
        v = c.temporal(self)
        c.touch_value(self.label(), v)
        return v

    def label(self):
        w = f"[{fmt_dur(self.lo)}, {fmt_dur(self.hi)}]"
        tgt = self.etype + (f".{self.fld}" if self.fld else "")
        return f"{self.op}{w}({tgt}{' where …' if self.cond else ''})"


@dataclass
class Since(Node):
    """since(B where p, A where q): a B happened and no A has happened since."""
    btype: str
    bcond: Node | None
    atype: str
    acond: Node | None
    nid: int = field(default_factory=lambda: next(_node_ids))
    def children(self): return [x for x in (self.bcond, self.acond) if x]
    def refs_current(self): return False
    def ev(self, c):
        v = c.since(self)
        c.touch_value(f"since({self.btype}, {self.atype})", v)
        return v


def truthy(v):
    return bool(v) and v is not None


def fmt_dur(s):
    for u, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s and s % n == 0:
            return f"{int(s // n)}{u}"
    return f"{int(s)}s"

# --------------------------------------------------------------------------- rules


ACTION_RANK = {"allow": 0, "step_up": 1, "hold": 2, "block": 3}


@dataclass
class Action:
    kind: str
    hold_secs: float = 0
    guardian: bool = False
    method: str | None = None

    def text(self):
        if self.kind == "hold":
            return f"hold {fmt_dur(self.hold_secs)}" + (" guardian" if self.guardian else "")
        if self.kind == "step_up":
            return "step_up" + (f" {self.method}" if self.method else "")
        return self.kind


@dataclass
class Rule:
    id: str
    name: str
    on: str
    where: Node | None
    action: Action
    explain: str = ""
    lesson: str = ""
    tags: list[str] = field(default_factory=list)
    source: str = ""
    line: int = 0
    i18n: dict = field(default_factory=dict)

    def text(self, lang="en"):
        t = self.i18n.get(lang, {})
        return t.get("explain", self.explain), t.get("lesson", self.lesson)

    def temporals(self):
        if not self.where:
            return []
        return [n for n in self.where.walk() if isinstance(n, (Temporal, Since))]

# --------------------------------------------------------------------------- parser


class Parser:
    def __init__(self, src: str):
        self.src = src
        self.toks = lex(src)
        self.i = 0

    # helpers
    @property
    def t(self): return self.toks[self.i]

    def at(self, kind, val=None):
        t = self.t
        return t.kind == kind and (val is None or t.val == val)

    def eat(self, kind, val=None):
        if not self.at(kind, val):
            want = val or kind
            raise ASPLError(f"expected {want}, found {self.t.val or self.t.kind}", self.t.line, self.t.col)
        tok = self.t
        self.i += 1
        return tok

    def opt(self, kind, val=None):
        if self.at(kind, val):
            return self.eat(kind, val)
        return None

    def ident(self):
        """A field name after a dot. Keywords are allowed here (account.guardian)."""
        if self.t.kind in ("name", "kw"):
            v = self.t.val
            self.i += 1
            return v
        raise ASPLError(f"expected a field name, found {self.t.val or self.t.kind}", self.t.line, self.t.col)

    # grammar
    def policy(self) -> list[Rule]:
        rules = []
        while not self.at("eof"):
            rules.append(self.rule())
        ids = [r.id for r in rules]
        dup = {x for x in ids if ids.count(x) > 1}
        if dup:
            raise ASPLError(f"duplicate rule id {sorted(dup)[0]}")
        return rules

    def rule(self) -> Rule:
        start = self.eat("kw", "rule")
        rid = self.eat("name").val
        name = self.eat("str").val
        self.eat("kw", "on")
        on = self.eat("name").val
        where = None
        if self.opt("kw", "where"):
            where = self.expr(scope="top")
        self.eat("kw", "then")
        action = self.action()
        explain = lesson = ""
        tags: list[str] = []
        i18n: dict[str, dict[str, str]] = {}
        while True:
            if self.at("kw", "explain") or self.at("kw", "lesson"):
                which = self.eat("kw").val
                lang = self.opt("name")          # explain hi "..." gives a translation
                text = self.eat("str").val
                if lang:
                    i18n.setdefault(lang.val, {})[which] = text
                elif which == "explain":
                    explain = text
                else:
                    lesson = text
            elif self.opt("kw", "tags"):
                self.eat("op", "[")
                tags.append(self.eat("name").val)
                while self.opt("op", ","):
                    tags.append(self.eat("name").val)
                self.eat("op", "]")
            else:
                break
        r = Rule(rid, name, on, where, action, explain, lesson, tags, line=start.line, i18n=i18n)
        for i, n in enumerate(r.temporals()):
            n.nid = f"{rid}#{i}"   # stable across processes, so monitor state survives a restart
            compile_temporal(n)
        return r

    def action(self) -> Action:
        if self.opt("kw", "allow"):
            return Action("allow")
        if self.opt("kw", "block"):
            return Action("block")
        if self.opt("kw", "step_up"):
            m = self.opt("name")
            return Action("step_up", method=m.val if m else None)
        if self.opt("kw", "hold"):
            d = self.eat("dur").val
            g = bool(self.opt("kw", "guardian"))
            return Action("hold", hold_secs=d, guardian=g)
        raise ASPLError("expected allow, step_up, hold or block", self.t.line, self.t.col)

    # expressions. scope: 'top' (bare names = current event) or 'past' (= past event)
    def expr(self, scope):
        return self.or_(scope)

    def or_(self, s):
        a = self.and_(s)
        while self.opt("kw", "or"):
            a = Bin("or", a, self.and_(s))
        return a

    def and_(self, s):
        a = self.not_(s)
        while self.opt("kw", "and"):
            a = Bin("and", a, self.not_(s))
        return a

    def not_(self, s):
        if self.opt("kw", "not"):
            return Unary("not", self.not_(s))
        return self.cmp(s)

    def cmp(self, s):
        a = self.sum_(s)
        for op in ("==", "!=", "<=", ">=", "<", ">"):
            if self.opt("op", op):
                return Bin(op, a, self.sum_(s))
        if self.opt("kw", "in"):
            return Bin("in", a, self.sum_(s))
        if self.at("kw", "not") and self.toks[self.i + 1].kind == "kw" and self.toks[self.i + 1].val == "in":
            self.i += 2
            return Bin("not in", a, self.sum_(s))
        return a

    def sum_(self, s):
        a = self.term(s)
        while self.at("op", "+") or self.at("op", "-"):
            op = self.eat("op").val
            a = Bin(op, a, self.term(s))
        return a

    def term(self, s):
        a = self.unary(s)
        while self.at("op", "*") or self.at("op", "/"):
            op = self.eat("op").val
            a = Bin(op, a, self.unary(s))
        return a

    def unary(self, s):
        if self.opt("op", "-"):
            return Unary("-", self.unary(s))
        return self.primary(s)

    def primary(self, s):
        t = self.t
        if t.kind in ("num", "dur"):
            self.i += 1
            return Lit(t.val)
        if t.kind == "str":
            self.i += 1
            return Lit(t.val)
        if self.opt("kw", "true"):
            return Lit(True)
        if self.opt("kw", "false"):
            return Lit(False)
        if self.opt("kw", "null"):
            return Lit(None)
        if self.opt("op", "("):
            e = self.expr(s)
            self.eat("op", ")")
            return e
        if self.opt("op", "{"):
            items = [self.setval()]
            while self.opt("op", ","):
                items.append(self.setval())
            self.eat("op", "}")
            return SetLit(items)
        if t.kind == "kw" and t.val in ("once", "never", "count", "distinct", "sum"):
            if s == "past":
                raise ASPLError("temporal operators cannot be nested", t.line, t.col)
            return self.temporal()
        if self.at("kw", "since"):
            if s == "past":
                raise ASPLError("temporal operators cannot be nested", t.line, t.col)
            return self.since()
        if self.opt("op", "$"):
            parts = []
            while self.opt("op", "."):
                parts.append(self.ident())
            if not parts:
                raise ASPLError("$ must be followed by .field", t.line, t.col)
            return Path("cur", parts)
        if t.kind == "name":
            self.i += 1
            if t.val == "graph" and self.at("op", "."):
                self.eat("op", ".")
                fn = self.eat("name").val
                self.eat("op", "(")
                args = []
                if not self.at("op", ")"):
                    args.append(self.expr(s))
                    while self.opt("op", ","):
                        args.append(self.expr(s))
                self.eat("op", ")")
                return Call("graph", fn, args)
            parts = []
            while self.opt("op", "."):
                parts.append(self.ident())
            if t.val in ("tel", "account"):
                if not parts:
                    raise ASPLError(f"{t.val} must be followed by .field", t.line, t.col)
                return Path(t.val, parts)
            # bare name: attribute of the event in scope. At top level that is the current event.
            return Path("cur" if s == "top" else "ev", [t.val] + parts)
        raise ASPLError(f"unexpected {t.val or t.kind}", t.line, t.col)

    def setval(self):
        t = self.t
        if t.kind in ("num", "str", "dur"):
            self.i += 1
            return t.val
        if t.kind in ("name", "kw"):
            self.i += 1
            return t.val
        raise ASPLError("bad set element", t.line, t.col)

    def window(self):
        self.eat("op", "[")
        lo = self.durnum()
        self.eat("op", ",")
        hi = self.durnum()
        self.eat("op", "]")
        if lo > hi:
            raise ASPLError("window lower bound is above the upper bound", self.t.line, self.t.col)
        return lo, hi

    def durnum(self):
        t = self.t
        if t.kind in ("dur", "num"):
            self.i += 1
            return float(t.val)
        raise ASPLError("expected a duration like 2h", t.line, t.col)

    def temporal(self):
        op = self.eat("kw").val
        lo, hi = self.window()
        self.eat("op", "(")
        etype = self.eat("name").val
        fld = None
        if self.opt("op", "."):
            fld = self.ident()
        if op in ("distinct", "sum") and not fld:
            raise ASPLError(f"{op} needs event.field, e.g. {op}[0,24h]({etype}.value)", self.t.line, self.t.col)
        cond = None
        if self.opt("kw", "where"):
            cond = self.expr(scope="past")
        self.eat("op", ")")
        return Temporal(op, lo, hi, etype, fld, cond)

    def since(self):
        self.eat("kw", "since")
        self.eat("op", "(")
        btype = self.eat("name").val
        bcond = self.expr("past") if self.opt("kw", "where") else None
        self.eat("op", ",")
        atype = self.eat("name").val
        acond = self.expr("past") if self.opt("kw", "where") else None
        self.eat("op", ")")
        for cnd in (bcond, acond):
            if cnd is not None and any(isinstance(n, Path) and n.root == "cur" for n in cnd.walk()):
                raise ASPLError("since() conditions cannot refer to $")
        return Since(btype, bcond, atype, acond)


def _conjuncts(n: Node) -> list[Node]:
    if isinstance(n, Bin) and n.op == "and":
        return _conjuncts(n.a) + _conjuncts(n.b)
    return [n]


def compile_temporal(n):
    """Choose a monitor layout. Sliced when the only link to the current event is one
    equality `pastfield == $expr`; buffered when $ appears anywhere else."""
    if isinstance(n, Since) or n.cond is None:
        return
    def match_key(cj):
        if not (isinstance(cj, Bin) and cj.op == "=="):
            return None
        for past, cur in ((cj.a, cj.b), (cj.b, cj.a)):
            if (isinstance(past, Path) and past.root == "ev" and len(past.parts) == 1
                    and cur.refs_current()
                    and not any(isinstance(x, Path) and x.root in ("ev", "tel") for x in cur.walk())):
                return past.parts[0], cur
        return None

    key = None
    rest = []
    for cj in _conjuncts(n.cond):
        if key is None:
            k = match_key(cj)
            if k:
                key = k
                continue
        rest.append(cj)
    residual = None
    for cj in rest:
        residual = cj if residual is None else Bin("and", residual, cj)
    residual_refs_cur = residual is not None and any(isinstance(x, Path) and x.root == "cur" for x in residual.walk())
    if residual_refs_cur:
        n.buffered = True
        n.slice_field = n.slice_cur = None
        n.residual = n.cond
    else:
        n.buffered = False
        n.slice_field, n.slice_cur = (key if key else (None, None))
        n.residual = residual


def parse_policy(src: str) -> list[Rule]:
    rules = Parser(src).policy()
    lines = src.splitlines()
    # attach each rule's source text for display
    starts = [r.line for r in rules] + [len(lines) + 1]
    for r, a, b in zip(rules, starts, starts[1:]):
        r.source = "\n".join(lines[a - 1:b - 1]).rstrip()
    return rules

# --------------------------------------------------------------------------- runtime


@dataclass
class Event:
    id: str
    ts: float
    bo: str
    type: str
    attrs: dict = field(default_factory=dict)
    tel: dict = field(default_factory=dict)


class Ctx:
    """Evaluation context for one rule at one event."""
    __slots__ = ("current", "scope_event", "account", "funcs", "monitors", "trace", "history")

    def __init__(self, current, account, funcs, monitors, history=None):
        self.current = current
        self.scope_event = current
        self.account = account
        self.funcs = funcs
        self.monitors = monitors
        self.history = history
        self.trace: dict[str, Any] = {}

    def touch_value(self, label, v):
        if len(self.trace) < 24:
            self.trace[label] = v

    def temporal(self, n: Temporal):
        return self.monitors.query(n, self)

    def since(self, n: Since):
        return self.monitors.query_since(n, self)


def eval_past(cond: Node | None, past: Event, c: Ctx) -> bool:
    if cond is None:
        return True
    saved = c.scope_event
    c.scope_event = past
    try:
        return truthy(cond.ev(c))
    finally:
        c.scope_event = saved


class _Win:
    """Timestamps (and optional values) in arrival order with a running sum and counts."""
    __slots__ = ("q", "total", "counts")

    def __init__(self):
        self.q: deque = deque()
        self.total = 0.0
        self.counts: dict = defaultdict(int)

    def add(self, ts, val):
        self.q.append((ts, val))
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            self.total += val
        self.counts[val] += 1

    def prune(self, before):
        q = self.q
        while q and q[0][0] < before:
            self._drop()

    def compact(self, upto):
        """For once/never only: if two timestamps are both at or before `upto`
        (= now - lo), the older one can never be the witness the newer is not,
        so drop it. State becomes O(events in the last `lo` seconds)."""
        q = self.q
        while len(q) >= 2 and q[1][0] <= upto:
            self._drop()

    def _drop(self):
        _, v = self.q.popleft()
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            self.total -= v
        self.counts[v] -= 1
        if self.counts[v] <= 0:
            del self.counts[v]


class Monitors:
    """Per-account state for every temporal node in a policy (incremental mode)."""

    def __init__(self, rules: list[Rule]):
        self.by_type: dict[str, list] = defaultdict(list)
        self.nodes = []
        seen = set()
        for r in rules:
            for n in r.temporals():
                if n.nid in seen:
                    continue
                seen.add(n.nid)
                self.nodes.append(n)
                if isinstance(n, Since):
                    self.by_type[n.btype].append(n)
                    if n.atype != n.btype:
                        self.by_type[n.atype].append(n)
                else:
                    self.by_type[n.etype].append(n)
        # state[(nid, bo)] -> _Win | dict[key->_Win] | list (buffered) | bool (since)
        self.state: dict = {}
        self.node_by_id = {n.nid: n for n in self.nodes}

    def sweep(self, now: float, budget: int | None = None) -> int:
        """Drop state that has aged out of every window. Returns entries removed.
        Without this, slice keys for old beneficiaries would accumulate forever.
        With a budget, visit at most that many keys and resume next call, so a
        sweep never pauses a decision for long."""
        removed = 0
        if budget is None:
            keys = list(self.state)
        else:
            if not getattr(self, "_cursor", None):
                self._cursor = list(self.state)
            keys, self._cursor = self._cursor[:budget], self._cursor[budget:]
        for k in keys:
            if k not in self.state:
                continue
            n = self.node_by_id.get(k[0])
            v = self.state[k]
            if n is None or isinstance(n, Since):
                continue
            if isinstance(v, _Win):
                v.prune(now - n.hi)
                if not v.q:
                    del self.state[k]; removed += 1
            elif isinstance(v, dict):
                for key in list(v):
                    v[key].prune(now - n.hi)
                    if not v[key].q:
                        del v[key]; removed += 1
                if not v:
                    del self.state[k]
            elif isinstance(v, deque):
                while v and v[0].ts < now - n.hi:
                    v.popleft()
                if not v:
                    del self.state[k]; removed += 1
        return removed

    def size(self) -> int:
        total = 0
        for v in self.state.values():
            if isinstance(v, _Win) or isinstance(v, deque):
                total += len(v.q) if isinstance(v, _Win) else len(v)
            elif isinstance(v, dict):
                total += sum(len(w.q) for w in v.values())
            else:
                total += 1
        return total

    def observe(self, e: Event, account, funcs):
        """Fold one event into the monitors. Must run before rules are evaluated on it."""
        nodes = self.by_type.get(e.type)
        if not nodes:
            return
        c = Ctx(e, account, funcs, self)
        for n in nodes:
            k = (n.nid, e.bo)
            if isinstance(n, Since):
                if e.type == n.btype and eval_past(n.bcond, e, c):
                    self.state[k] = True
                elif e.type == n.atype and eval_past(n.acond, e, c):
                    self.state[k] = False
                continue
            if n.buffered:
                buf = self.state.setdefault(k, deque())
                buf.append(e)
                while buf and buf[0].ts < e.ts - n.hi:
                    buf.popleft()
                continue
            if not eval_past(n.residual, e, c):
                continue
            val = e.attrs.get(n.fld) if n.fld else None
            if n.slice_field:
                key = e.attrs.get(n.slice_field)
                w = self.state.setdefault(k, {}).setdefault(key, _Win())
            else:
                w = self.state.get(k)
                if w is None:
                    w = self.state[k] = _Win()
            w.add(e.ts, val)
            w.prune(e.ts - n.hi)
            if n.op in ("once", "never"):
                w.compact(e.ts - n.lo)

    def query(self, n: Temporal, c: Ctx):
        now = c.current.ts
        k = (n.nid, c.current.bo)
        if n.buffered:
            buf = self.state.get(k, ())
            items = [(p.ts, p.attrs.get(n.fld) if n.fld else None) for p in buf
                     if now - n.hi <= p.ts <= now - n.lo and eval_past(n.residual, p, c)]
            return _aggregate(n, items)
        if n.slice_field:
            key = n.slice_cur.ev(c)
            w = self.state.get(k, {}).get(key)
        else:
            w = self.state.get(k)
        if w is None:
            return _aggregate(n, [])
        w.prune(now - n.hi)
        if n.op in ("once", "never"):
            w.compact(now - n.lo)
        if n.lo == 0:
            if n.op in ("once", "never"):
                hit = bool(w.q)
                return hit if n.op == "once" else not hit
            if n.op == "count":
                return len(w.q)
            if n.op == "distinct":
                return len(w.counts)
            if n.op == "sum":
                return w.total
        items = [(ts, v) for ts, v in w.q if ts <= now - n.lo]
        return _aggregate(n, items)

    def query_since(self, n: Since, c: Ctx):
        return bool(self.state.get((n.nid, c.current.bo), False))


def _aggregate(n: Temporal, items):
    if n.op == "once":
        return bool(items)
    if n.op == "never":
        return not items
    if n.op == "count":
        return len(items)
    if n.op == "distinct":
        return len({v for _, v in items})
    if n.op == "sum":
        return float(sum(v for _, v in items if isinstance(v, (int, float)) and not isinstance(v, bool)))
    raise ASPLError(f"bad temporal op {n.op}")


class ReferenceMonitors:
    """Brute-force semantics: scan the whole account history at every query."""

    def __init__(self):
        self.history: dict[str, list[Event]] = defaultdict(list)

    def observe(self, e: Event, account, funcs):
        self.history[e.bo].append(e)

    def query(self, n: Temporal, c: Ctx):
        now = c.current.ts
        items = []
        for p in self.history[c.current.bo]:
            if p.type == n.etype and now - n.hi <= p.ts <= now - n.lo and eval_past(n.cond, p, c):
                items.append((p.ts, p.attrs.get(n.fld) if n.fld else None))
        return _aggregate(n, items)

    def query_since(self, n: Since, c: Ctx):
        for p in reversed(self.history[c.current.bo]):
            if p.type == n.btype and eval_past(n.bcond, p, c):
                return True
            if p.type == n.atype and eval_past(n.acond, p, c):
                return False
        return False


@dataclass
class Hit:
    rule: Rule
    trace: dict


def evaluate_rules(rules_by_type: dict[str, list[Rule]], e: Event, account, funcs, monitors) -> list[Hit]:
    """Run every rule bound to e.type. Call monitors.observe(e) first."""
    hits = []
    for r in rules_by_type.get(e.type, ()):
        c = Ctx(e, account, funcs, monitors)
        if r.where is None or truthy(r.where.ev(c)):
            hits.append(Hit(r, c.trace))
    return hits


def index_rules(rules: list[Rule]) -> dict[str, list[Rule]]:
    d: dict[str, list[Rule]] = defaultdict(list)
    for r in rules:
        d[r.on].append(r)
    return d


# --------------------------------------------------------------------------- static checks

def lint(rules: list[Rule], event_attrs: dict[str, list[str]], tel_fields: set[str],
         account_fields: set[str], graph_funcs: set[str]) -> list[dict]:
    """Catch policy mistakes before deployment. A misspelt field evaluates to null
    and silently disables a rule, so unknown names are errors, not warnings."""
    issues = []

    def add(level, r, msg):
        issues.append({"level": level, "rule": r.id, "line": r.line, "msg": msg})

    def check(node, r, scope_type):
        for x in node.walk():
            if isinstance(x, Path):
                head = x.parts[0]
                if x.root == "tel" and head not in tel_fields:
                    add("error", r, f"unknown telemetry field tel.{head}")
                elif x.root == "account" and head not in account_fields:
                    add("error", r, f"unknown account field account.{head}")
                elif x.root == "cur" and head not in event_attrs.get(r.on, ()):
                    add("error", r, f"'{r.on}' events have no field '{head}'")
                elif x.root == "ev" and scope_type and head not in event_attrs.get(scope_type, ()):
                    add("error", r, f"'{scope_type}' events have no field '{head}'")
            elif isinstance(x, Call) and f"{x.ns}.{x.fn}" not in graph_funcs:
                add("error", r, f"unknown function {x.ns}.{x.fn}")

    for r in rules:
        if r.on not in event_attrs:
            add("error", r, f"no event type '{r.on}'")
            continue
        if not r.explain:
            add("warning", r, "no explanation: investors on hold would see no reason")
        if r.action.kind in ("hold", "block") and not r.lesson:
            add("info", r, "no lesson text for the investor")
        if r.action.kind == "hold" and r.action.hold_secs > 7 * 86400:
            add("warning", r, "hold longer than 7 days")
        if r.where is None and r.action.kind in ("hold", "block"):
            add("warning", r, f"unconditional {r.action.kind} on every {r.on} event")
        if r.where is None:
            continue
        # top-level expression, temporal internals are checked in their own scope
        top = [n for n in r.where.walk()]
        inner = set()
        for n in top:
            if isinstance(n, Temporal):
                if n.etype not in event_attrs:
                    add("error", r, f"temporal operator over unknown event type '{n.etype}'")
                elif n.fld and n.fld not in event_attrs[n.etype]:
                    add("error", r, f"'{n.etype}' events have no field '{n.fld}'")
                if n.cond is not None:
                    check(n.cond, r, n.etype)
                    inner.update(id(x) for x in n.cond.walk())
                if n.buffered:
                    add("info", r, f"{n.label()} uses a bounded buffer (cost grows with events in the window)")
                if n.hi > 365 * 86400:
                    add("warning", r, f"window longer than a year in {n.label()}")
            elif isinstance(n, Since):
                for t, cnd in ((n.btype, n.bcond), (n.atype, n.acond)):
                    if t not in event_attrs:
                        add("error", r, f"since() over unknown event type '{t}'")
                    elif cnd is not None:
                        check(cnd, r, t)
                        inner.update(id(x) for x in cnd.walk())
        for n in top:
            if id(n) in inner:
                continue
            if isinstance(n, Path) or isinstance(n, Call):
                check(n, r, None)
    seen = set()
    out = []
    for i in issues:  # de-duplicate
        k = (i["rule"], i["msg"])
        if k not in seen:
            seen.add(k); out.append(i)
    return out
