"""ASPL parser and monitor semantics, including a differential test of the
incremental monitors against the brute-force reference evaluator."""
import random

import pytest

from backend import aspl
from backend.aspl import Event, Monitors, ReferenceMonitors, ASPLError

ACCT = {"bo": "X", "cap": 100, "guardian": True}
FUNCS = {}


def run(src, events, ref=False):
    rules = aspl.parse_policy(src)
    mon = ReferenceMonitors() if ref else Monitors(rules)
    idx = aspl.index_rules(rules)
    out = []
    for e in events:
        mon.observe(e, ACCT, FUNCS)
        out.append(sorted(h.rule.id for h in aspl.evaluate_rules(idx, e, ACCT, FUNCS, mon)))
    return out


def ev(ts, typ, bo="A", tel=None, **attrs):
    return Event(f"{bo}{ts}{typ}", ts, bo, typ, attrs, tel or {})


# ---------------------------------------------------------------- parser
def test_parses_default_policy():
    src = open("policies/default.aspl", encoding="utf8").read()
    rules = aspl.parse_policy(src)
    assert len(rules) >= 20
    assert all(r.explain for r in rules)
    assert len({r.id for r in rules}) == len(rules)


def test_error_has_line_and_column():
    with pytest.raises(ASPLError) as e:
        aspl.parse_policy('rule A "x"\n  on t\n  where value >\n  then allow')
    assert e.value.line == 4


def test_keyword_allowed_as_field():
    r = aspl.parse_policy('rule A "x" on t where account.guardian then allow')[0]
    assert r.where.parts == ["guardian"]


def test_duplicate_ids_rejected():
    with pytest.raises(ASPLError):
        aspl.parse_policy('rule A "x" on t then allow rule A "y" on t then allow')


def test_nested_temporal_rejected():
    with pytest.raises(ASPLError):
        aspl.parse_policy('rule A "x" on t where once[0,1h](u where once[0,1h](v)) then allow')


def test_compile_layouts():
    rules = aspl.parse_policy('''
      rule S "sliced" on t where once[0,1h](u where k == $.k and x > 1) then allow
      rule B "buffered" on t where once[0,1h](u where x > $.x) then allow
      rule P "plain" on t where count[0,1h](u where x > 1) >= 2 then allow''')
    s, b, p = (r.temporals()[0] for r in rules)
    assert s.slice_field == "k" and not s.buffered
    assert b.buffered
    assert p.slice_field is None and not p.buffered


# ---------------------------------------------------------------- semantics
def test_window_includes_current_and_boundaries():
    src = 'rule W "w" on t where count[0, 10s](t) >= 2 then allow'
    out = run(src, [ev(0, "t"), ev(10, "t"), ev(21, "t")])
    assert out == [[], ["W"], []]   # at 10 the window [0,10] holds both; at 21 it is [11,21]


def test_lower_bound_excludes_recent():
    src = 'rule N "n" on t where never[5s, 1h](t) then allow'
    out = run(src, [ev(0, "t"), ev(3, "t"), ev(6, "t")])
    assert out == [["N"], ["N"], []]


def test_slice_by_key():
    src = 'rule K "k" on pay where once[0, 1h](add where to == $.to) then allow'
    out = run(src, [ev(0, "add", to="M1"), ev(10, "pay", to="M2"), ev(20, "pay", to="M1")])
    assert out == [[], [], ["K"]]


def test_accounts_are_isolated():
    src = 'rule K "k" on pay where once[0, 1h](add) then allow'
    out = run(src, [ev(0, "add", bo="A"), ev(1, "pay", bo="B"), ev(2, "pay", bo="A")])
    assert out == [[], [], ["K"]]


def test_since():
    src = 'rule S "s" on x where since(on_, off) then allow'
    out = run(src, [ev(0, "x"), ev(1, "on_"), ev(2, "x"), ev(3, "off"), ev(4, "x")])
    assert out == [[], [], ["S"], [], []]


def test_distinct_and_sum():
    src = '''rule D "d" on out where distinct[0, 1d](inp.src) >= 3 then allow
             rule S "s" on out where sum[0, 1d](out.v) >= 100 then allow'''
    evs = [ev(0, "inp", src="a"), ev(1, "inp", src="b"), ev(2, "inp", src="a"), ev(3, "out", v=60),
           ev(4, "inp", src="c"), ev(5, "out", v=40)]
    assert run(src, evs) == [[], [], [], [], [], ["D", "S"]]


def test_missing_values_never_satisfy_comparisons():
    src = 'rule M "m" on t where tel.sim_swap_age_h < 72 then allow'
    assert run(src, [ev(0, "t", tel={})]) == [[]]


# ---------------------------------------------------------------- differential
TYPES = ["a", "b", "c"]


def rand_temporal(rng):
    op = rng.choice(["once", "never", "count", "distinct", "sum"])
    lo = rng.choice([0, 0, 0, 5, 30])
    hi = lo + rng.choice([10, 60, 300])
    et = rng.choice(TYPES)
    cond = rng.choice([
        None, "k == $.k", "x > 1", "tel.f", "k == $.k and x >= 2", "x > $.x", "x == $.x or tel.f",
        "not tel.f and k != 0", "$.k == k and tel.f",
    ])
    tgt = et + (".x" if op in ("distinct", "sum") else "")
    inner = f"{tgt} where {cond}" if cond else tgt
    t = f"{op}[{lo}s, {hi}s]({inner})"
    if op == "count":
        t += f" >= {rng.randint(1, 4)}"
    elif op == "distinct":
        t += f" >= {rng.randint(1, 3)}"
    elif op == "sum":
        t += f" >= {rng.randint(1, 8)}"
    return t


def rand_policy(rng, n):
    rules = []
    for i in range(n):
        e = rand_temporal(rng)
        r = rng.random()
        if r < 0.3:
            e = f"{e} and {rand_temporal(rng)}"
        elif r < 0.5:
            e = f"not ({e}) or {rand_temporal(rng)}"
        elif r < 0.6:
            e = f"since({rng.choice(TYPES)} where x > 0, {rng.choice(TYPES)}) and {e}"
        rules.append(f'rule R{i} "r" on {rng.choice(TYPES)} where {e} then allow')
    return "\n".join(rules)


def rand_trace(rng, n):
    t, out = 0, []
    for i in range(n):
        t += rng.choice([0, 0, 1, 2, 5, 9, 20, 40])
        out.append(Event(f"e{i}", t, rng.choice(["A", "B", "C"]), rng.choice(TYPES),
                         {"k": rng.randint(0, 2), "x": rng.randint(0, 3)}, {"f": rng.random() < 0.4}))
    return out


@pytest.mark.parametrize("seed", range(60))
def test_incremental_matches_reference(seed):
    rng = random.Random(seed)
    src = rand_policy(rng, 6)
    trace = rand_trace(rng, 250)
    rules = aspl.parse_policy(src)
    inc, ref = Monitors(rules), ReferenceMonitors()
    idx = aspl.index_rules(rules)
    nodes = [n for r in rules for n in r.temporals()]
    for e in trace:
        inc.observe(e, ACCT, FUNCS)
        ref.observe(e, ACCT, FUNCS)
        hi = sorted(h.rule.id for h in aspl.evaluate_rules(idx, e, ACCT, FUNCS, inc))
        hr = sorted(h.rule.id for h in aspl.evaluate_rules(idx, e, ACCT, FUNCS, ref))
        assert hi == hr, f"seed {seed} event {e.id}\n{src}"
        # every temporal node, queried at every event, must agree too
        for n in nodes:
            ci, cr = aspl.Ctx(e, ACCT, FUNCS, inc), aspl.Ctx(e, ACCT, FUNCS, ref)
            assert n.ev(ci) == n.ev(cr), f"seed {seed} node {n.label() if hasattr(n, 'label') else 'since'} at {e.id}"
