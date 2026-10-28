# Production readiness

What a depository needs before AgentSnap could hold a real investor's transfer, what this build already does, and how each piece is verified. Numbers are from this machine (Windows, one Python process); rerun the commands to reproduce.

## Built and verified

| Concern | What the code does | Evidence |
|---|---|---|
| Correct temporal semantics | Incremental monitors checked against a brute-force reference on random policies and traces | 60 differential tests; an injected off-by-one fails 61 tests |
| Bounded memory | once/never windows compact to the latest witness; stale slices swept incrementally (2,000 keys per 1,000 events) | `test_sweep_keeps_state_bounded`: state stays flat over 6,000 hours of history |
| Cost independent of history | Per-event cost stays near 30-85 µs from 1,000 to 50,000 past events; a full scan reaches 2,861 µs | `python -m backend.microbench` |
| Idempotent ingest | Retried event IDs return the original decision (`Idempotent-Replay: true`), never double-count windows | `test_duplicate_event_returns_original_decision`, API test |
| Out-of-order events | A late event is processed at the account's latest time and flagged on the decision | `test_late_event_processed_at_account_time_and_flagged` |
| Engine failure | Value-moving events fail closed into a 4-hour guardian hold; others fail open; every error counted and audited | `test_engine_error_fails_closed_for_value_events` |
| Telecom feed outage | Circuit breaker per provider; caller registry down means "unverified" (fails closed); SIM-swap lookups cached for 10 minutes; degradation written on the decision | `test_caller_registry_outage_fails_closed_and_is_recorded`, Operations drill |
| Crash recovery | Every input (events and hold actions) goes to an append-only log; snapshots capture all state with the log position; restore replays the tail | `test_crash_recovery_reaches_identical_state`; console drill: snapshot at input 5,801, 6,008 replayed in 1.1 s, identical state fingerprint |
| Tamper-evident audit | SHA-256 hash chain plus Ed25519-signed checkpoints every 1,000 records and at shutdown; public key exportable | `test_signed_checkpoints_catch_a_full_chain_rewrite`; console "insider rewrite" demo |
| Safe policy changes | Static checker rejects unknown fields, telemetry signals, graph functions and event types; shadow deployment evaluates live traffic without acting; promotion keeps warm monitor state; every version recorded | `test_misspelt_field_is_rejected`, `test_shadow_policy_records_disagreement_then_promotes`; live: 3,419 events, 0.058% disagreement, then promoted |
| Hold lifecycle | State machine; plain holds release at expiry; guardian holds escalate to the DP instead of releasing | `test_hold_expiry_state_machine` |
| Integration API | `/v1` with API keys and roles (ingest, analyst, admin), per-key rate limit, strict schemas (unknown fields rejected, raw phone numbers rejected), batch ingest, hold actions, policy lifecycle, snapshot and drills | `tests/test_prod.py` API tests; OpenAPI at `/docs` |
| Console exposure | Console routes answer only on localhost unless explicitly opened | `test_console_api_refuses_remote_clients` |
| Operability | `/healthz`, `/readyz` (reports degraded providers), Prometheus `/metrics` with latency histogram and per-rule counters; graceful shutdown signs the final audit head | Operations view; API tests |
| Inclusion | Rules carry per-language explanations (`explain hi "…"`); API returns them with `?lang=hi`; investor app has a Hindi toggle | `test_api_decision_idempotency_and_hindi` |
| Packaging | `requirements.txt`, Dockerfile (non-root, healthcheck), CI workflow running tests, policy lint and a benchmark floor | `Dockerfile`, `.github/workflows/ci.yml` |

## Measured

| | |
|---|---|
| Benchmark, 10,000 accounts, 30 days, 184,459 events, 420 attacks | 97.6% stopped before loss; 0.144% of 15,252 legitimate actions held |
| In-process pipeline, everything on (telemetry, graph, 27 rules, input log, audit chain, signing) | p50 51 µs, p99 244 µs, 10,150 events/s on one core |
| HTTP, single events, 16 concurrent clients over 4 processes | 512 events/s, p50 27 ms, p99 57 ms, 16,000/16,000 succeeded |
| HTTP, batches of 100 | about 2,300 to 2,900 events/s |
| Recovery | 6,008 inputs replayed in 1.1 s |

The HTTP figures are bound by Python web-framework overhead on a single Windows process (the engine itself is about 0.2 ms of each request). They are the reason the production design shards by BO account, below.

## Still required before go-live (not code)

Each item below has a workaround that is built and tested; see [GO_LIVE.md](GO_LIVE.md).

| Item | Why | Path |
|---|---|---|
| Real data | False-hold rate on real investors is unknown until measured | 3 months in shadow mode on CDSL's event stream; no holds |
| Telecom feeds | Stand-ins here | DoT DIP for FRI and MNRL, TRAI 1600 registry sync, CAMARA SIM Swap and Number Verification via Airtel, Jio and Vi |
| Settlement delay | A hold needs a short cooling window in the off-market and pledge workflow | SEBI regulatory sandbox; opt-in seniors first |
| Horizontal scale | 18.59 crore accounts | Partition by BO (all state is per account); one engine per partition behind a log such as Kafka; snapshots per partition |
| Key management | Signing key is a file or ephemeral here | HSM-held Ed25519 key; rotate and publish public keys |
| Security review | No external review yet | Penetration test, CERT-In empanelled audit, threat model for the SDK |
| Privacy | Design is minimal-data, but not assessed | DPDP Act data protection impact assessment; retention limits on the input log |
| SDK | Device signals are in the event envelope here | Android and iOS SDK in myEasi and DP apps (TelephonyCallback, MediaProjection, Play Integrity, App Attest) |
| Mule model | Weights hand-set | Fit on confirmed mule accounts; share signals with NSDL |
| Known gap | "Patient caller" variant passes 4 times in 10 | Per-investor behaviour baselines and cross-depository receiver intelligence |
