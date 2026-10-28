# Go-live: why each item exists, and the workaround

| Item | Why it is needed | Workaround built | What it does not replace |
|---|---|---|---|
| Real traffic | The benchmark is synthetic. A rule that holds 0.14% of simulated actions could hold 1% of real ones, and every false hold is an investor who cannot move their own shares. | `backend/shadow_replay.py`: a DP or broker runs it on its own exported event log, on its own machine, with an optional list of BOs that filed fraud complaints. Output: false-hold rate and catches. No data leaves the building, so no data-sharing agreement is needed to start. | Months of live shadow mode on CDSL's own stream before any hold is enforced. |
| Telecom feeds | Without the 1600 registry, FRI and MNRL, every caller looks "unknown"; without SIM-swap data the takeover rules go quiet. | `backend/feeds.py`: CSV loader for the three lists (hashes on load, atomic swap, rejects a bad file whole) and a CAMARA SIM Swap client with OAuth2, timeouts and a cache, tested against a mock that speaks the published request shapes. DoT already shares FRI with banks; GSMA reports SIM Swap live on Airtel, Jio and Vi. | Commercial access to the operator APIs. |
| Cooling-off window | Delaying an instruction after it is submitted changes settlement, which needs SEBI approval. | The pause happens at the authorisation step, before an instruction exists, with the investor's consent (the same footing as SEBI's January 2024 voluntary freeze framework). Accounts without consent get a liveness challenge and a warning instead (`cooling_consent`). | A formal SEBI view; the sandbox remains the clean route for default-on pauses. |
| Signing key | A key in a file can be copied by whoever runs the server. | Encrypted keystore (PKCS#8 with a passphrase), key IDs on every checkpoint, rotation recorded in the chain, and a **witness log**: every signed head is appended to a file meant to be published outside the depository (an auditor, SEBI, a public repository). Rewriting history then means changing someone else's copy too. | An HSM, which removes the copy risk entirely. |
| Security audit | Fraud infrastructure is itself a target. | Request-size cap, security headers and a strict CSP, localhost-only console, per-key roles and rate limits, strict schemas that refuse raw phone numbers, fail-closed defaults; all tested. Threat model below. | An independent penetration test and a CERT-In empanelled audit. |
| DPDP assessment | The system processes behaviour and telecom signals about investors. | Data minimisation by design (hashes and booleans only), a data-access export per BO (`/v1/privacy/export/{bo}`), and retention that purges old inputs without breaking recovery (`/v1/admin/retention`). | A formal data protection impact assessment and a Data Protection Officer's sign-off. |
| Mobile SDK | Call state and screen sharing are only visible to a native app. | `sdk/agentsnap.js` (web: device binding, paste detection, hesitation z-score with the baseline kept on the device; tested) and `sdk/android/AgentSnapSignals.kt` (reference implementation of call state, screen mirroring, remote-control apps and accessibility overlays; not compiled here). | A shipped, reviewed SDK inside myEasi and DP apps. |
| Patient-caller gap | The scammer has the victim hang up and send a small amount the next day. Depository signals alone cannot tell this from a real gift; a default rule for it held grandparents' gifts to new family accounts. | An opt-in **new-beneficiary lock** (rule B6): the investor or their family chooses a 12-hour pause on transfers to accounts added that week. With every senior who has a guardian opted in, the variant's catch rate rises from 45% to 82%; the cost is pauses on transfers those investors asked to have paused. | Per-investor behaviour baselines from the native SDK, and receiver intelligence shared with NSDL. |

## Threat model (short)

| Threat | Control |
|---|---|
| Stolen API key used to inject events | Per-key roles and rate limit; ingest keys cannot change policy or act as analysts; every input logged |
| Insider edits a decision | Hash chain, Ed25519 checkpoints, published witness log |
| Malicious policy disables protection | Admin-only deploy, static checker, shadow first, every version in the chain |
| Feed outage used as cover | Caller registry down means "unverified" (fails closed); degradation written on each decision |
| Oversized or malformed payloads | 1 MB cap before parsing; schemas reject unknown fields |
| Console reached from outside | Console routes answer on localhost only |
| Raw personal data leaks from logs | Numbers are keyed hashes on the device; IP kept to /24; no audio, screen or contacts collected |
