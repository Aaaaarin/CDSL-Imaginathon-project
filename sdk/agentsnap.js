/* AgentSnap web SDK. Collects the signals a browser can see and sends only
 * derived values: a device id, how long it has been bound, whether the beneficiary
 * was pasted, and a hesitation z-score against this investor's own baseline, which
 * never leaves the device. Call state and screen sharing need the native SDK.
 *
 *   const as = AgentSnap.init({ endpoint: "/v1/events", apiKey: "…" });
 *   as.watch(document.querySelector("#beneficiary"));      // paste + dwell timing
 *   const decision = await as.send({ event_id, ts, bo, type: "offmarket_out", attrs });
 */
(function (root) {
  "use strict";
  const store = {
    get(k) { try { return JSON.parse(localStorage.getItem("agentsnap." + k)); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem("agentsnap." + k, JSON.stringify(v)); } catch (e) { /* private mode */ } },
  };

  function deviceId() {
    let d = store.get("device");
    if (!d) {
      const r = (root.crypto && root.crypto.randomUUID) ? root.crypto.randomUUID() : String(Math.random()).slice(2) + Date.now();
      d = { id: "web-" + r, bound: Date.now() };
      store.set("device", d);
    }
    return d;
  }

  // Welford running mean and variance of dwell time (ms) for this investor
  function baseline() { return store.get("dwell") || { n: 0, mean: 0, m2: 0 }; }
  function learn(ms) {
    const b = baseline();
    b.n += 1;
    const d = ms - b.mean;
    b.mean += d / b.n;
    b.m2 += d * (ms - b.mean);
    store.set("dwell", b);
  }
  function zscore(ms) {
    const b = baseline();
    if (b.n < 5) return 0;                     // not enough history to judge
    const sd = Math.sqrt(b.m2 / (b.n - 1)) || 1;
    return Math.max(-20, Math.min(20, (ms - b.mean) / sd));
  }

  function init(opts) {
    const cfg = Object.assign({ endpoint: "/v1/events", apiKey: null, lang: "en" }, opts || {});
    const state = { pasted: false, focusAt: null, dwell: null };

    function watch(el) {
      if (!el) return;
      el.addEventListener("paste", () => { state.pasted = true; });
      el.addEventListener("focus", () => { state.focusAt = performance.now(); });
      el.addEventListener("blur", () => { if (state.focusAt) state.dwell = performance.now() - state.focusAt; });
    }

    function envelope() {
      const d = deviceId();
      const t = {
        device_id: d.id,
        device_age_h: Math.round((Date.now() - d.bound) / 36e5 * 10) / 10,
        paste_beneficiary: state.pasted,
      };
      if (state.dwell != null) { t.hesitation_z = Math.round(zscore(state.dwell) * 100) / 100; learn(state.dwell); }
      return t;
    }

    async function send(event) {
      const body = Object.assign({}, event, { tel: Object.assign(envelope(), event.tel || {}) });
      const r = await fetch(cfg.endpoint + "?lang=" + cfg.lang, {
        method: "POST",
        headers: Object.assign({ "Content-Type": "application/json" }, cfg.apiKey ? { "X-API-Key": cfg.apiKey } : {}),
        body: JSON.stringify(body),
      });
      state.pasted = false; state.dwell = null;
      if (!r.ok) throw new Error("AgentSnap " + r.status);
      return r.json();
    }

    return { watch, envelope, send };
  }

  const api = { init, _zscore: zscore, _learn: learn };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.AgentSnap = api;
})(typeof window !== "undefined" ? window : globalThis);
