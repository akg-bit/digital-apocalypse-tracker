(() => {
  "use strict";

  const REFRESH_MS = 5 * 60 * 1000;
  const PAGE = 60;
  const CATS = {
    cyber:   { label: "All cyber", color: "#f43f5e" },
    ransomware: { label: "Ransomware", color: "var(--c-ransomware)" },
    data_breach: { label: "Data breach", color: "var(--c-data_breach)" },
    ddos: { label: "DDoS", color: "var(--c-ddos)" },
    cyberattack: { label: "Cyberattack", color: "var(--c-cyberattack)" },
    exploited_vulnerability: { label: "Exploited vuln", color: "var(--c-exploited_vulnerability)" },
    outage: { label: "Outage", color: "var(--c-outage)" },
  };
  const LEVEL_COLORS = ["", "var(--lvl-1)", "var(--lvl-2)", "var(--lvl-3)", "var(--lvl-4)", "var(--lvl-5)"];

  const $ = (id) => document.getElementById(id);
  const state = { events: [], status: null, cat: "all", shown: PAGE, lastSeen: 0, loadedAt: 0, error: false };

  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* storage blocked */ } },
  };
  state.lastSeen = Number(store.get("dat:lastVisit")) || 0;

  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === "class") n.className = v;
      else if (k === "style") n.style.cssText = v;
      else n.setAttribute(k, v);
    }
    for (const k of kids.flat()) if (k != null && k !== false) n.append(k instanceof Node ? k : String(k));
    return n;
  }

  const fmtTime = (d) => d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const fmtDay = (d) => d.toLocaleDateString([], { weekday: "long", month: "short", day: "numeric", year: d.getFullYear() !== new Date().getFullYear() ? "numeric" : undefined });
  const fmtFull = (d) => d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZoneName: "short" });
  const tzName = (() => { try { return new Intl.DateTimeFormat([], { timeZoneName: "short" }).formatToParts(new Date()).find((p) => p.type === "timeZoneName").value; } catch (e) { return ""; } })();

  function ago(ms) {
    const s = Math.max(0, Math.round(ms / 1000));
    if (s < 60) return s + "s ago";
    const m = Math.round(s / 60);
    if (m < 60) return m + " min ago";
    const h = Math.round(m / 60);
    if (h < 48) return h + "h ago";
    return Math.round(h / 24) + "d ago";
  }
  function dur(a, b) {
    const m = Math.round((b - a) / 60000);
    if (m < 60) return m + "m";
    const h = Math.floor(m / 60);
    if (h < 48) return h + "h " + (m % 60) + "m";
    return Math.round(h / 24) + "d";
  }

  async function getJSON(path) {
    const r = await fetch(path + "?t=" + Date.now(), { cache: "no-store" });
    if (!r.ok) throw new Error(path + " " + r.status);
    return r.json();
  }

  async function load() {
    try {
      const [ev, st] = await Promise.all([getJSON("data/events.json"), getJSON("data/status.json").catch(() => null)]);
      state.events = (ev.events || []).map((e) => ({
        ...e,
        _start: new Date(e.started_at || e.reported_at),
        _rep: new Date(e.reported_at || e.started_at),
        _upd: new Date(e.updated_at || e.reported_at),
        _text: [e.headline, e.target, e.alleged_cause, e.attributed_to, e.detail, (e.sources || []).map((s) => s.name).join(" ")].join(" ").toLowerCase(),
      }));
      state.status = st;
      state.loadedAt = Date.now();
      state.error = false;
    } catch (err) {
      state.error = true;
      console.error(err);
    }
    render();
  }

  function filtered() {
    const q = $("q").value.trim().toLowerCase();
    const days = Number($("range").value);
    const minSev = Number($("sev").value);
    const ongoingOnly = $("ongoingOnly").checked;
    const since = Date.now() - days * 86400000;
    return state.events.filter((e) => {
      if (state.cat === "cyber" && e.category === "outage") return false;
      if (state.cat !== "all" && state.cat !== "cyber" && e.category !== state.cat) return false;
      if (e.severity < minSev) return false;
      if (ongoingOnly && !e.ongoing) return false;
      if (e._rep.getTime() < since && !e.ongoing) return false;
      if (q && !q.split(/\s+/).every((w) => e._text.includes(w))) return false;
      return true;
    }).sort((a, b) => b._rep - a._rep);
  }

  function renderThreat() {
    const t = (state.status && state.status.threat) || { level: 1, label: "NOMINAL", score: 0 };
    const label = $("threatLabel");
    label.textContent = t.label;
    $("threat").style.setProperty("--lvl", LEVEL_COLORS[t.level] || "");
    const meter = $("meter");
    meter.setAttribute("aria-valuenow", t.level);
    meter.setAttribute("aria-valuetext", t.label);
    [...meter.children].forEach((i, idx) => i.classList.toggle("on", idx < t.level));
  }

  function renderStats() {
    const now = Date.now();
    const d1 = state.events.filter((e) => now - e._rep < 86400000);
    const d7 = state.events.filter((e) => now - e._rep < 7 * 86400000);
    const cyber7 = d7.filter((e) => e.category !== "outage").length;
    const out7 = d7.filter((e) => e.category === "outage").length;
    const ongoing = state.events.filter((e) => e.ongoing).length;
    const worst = d7.reduce((m, e) => (e.severity > (m ? m.severity : 0) ? e : m), null);
    const box = $("stats");
    box.replaceChildren(
      el("div", { class: "stat" }, el("b", {}, d1.length), el("span", {}, "incidents, last 24h")),
      el("div", { class: "stat" }, el("b", { style: "color:var(--c-cyberattack)" }, cyber7), el("span", {}, "cyber incidents, 7 days")),
      el("div", { class: "stat" }, el("b", { style: "color:var(--c-outage)" }, out7), el("span", {}, "major outages, 7 days")),
      el("div", { class: "stat" }, el("b", { style: ongoing ? "color:var(--red)" : "" }, ongoing), el("span", {}, "ongoing right now")),
    );
    if (worst) box.append(el("div", { class: "stat" }, el("b", { class: "worst", title: worst.headline }, worst.target || worst.headline), el("span", {}, "worst this week · severity " + worst.severity)));
  }

  function renderChips() {
    const counts = {};
    const days = Number($("range").value);
    const since = Date.now() - days * 86400000;
    for (const e of state.events) {
      if (e._rep < since && !e.ongoing) continue;
      counts[e.category] = (counts[e.category] || 0) + 1;
      counts.all = (counts.all || 0) + 1;
      if (e.category !== "outage") counts.cyber = (counts.cyber || 0) + 1;
    }
    const chips = [["all", "Everything", "var(--text)"], ...Object.entries(CATS).map(([k, v]) => [k, v.label, v.color])];
    $("chips").replaceChildren(...chips.map(([k, label, color]) => {
      const b = el("button", { class: "chip", type: "button", "aria-pressed": String(state.cat === k), style: "--sw:" + color },
        k === "all" ? null : el("span", { class: "sw" }), label, el("small", {}, counts[k] || 0));
      b.addEventListener("click", () => { state.cat = k; state.shown = PAGE; render(); });
      return b;
    }));
  }

  function eventCard(e) {
    const cat = CATS[e.category] || { label: e.category, color: "var(--muted)" };
    const isNew = state.lastSeen && e._rep.getTime() > state.lastSeen;
    const pips = el("span", { class: "pips", title: "Severity " + e.severity + " of 5", "aria-label": "Severity " + e.severity + " of 5", style: "--pip:" + LEVEL_COLORS[e.severity] },
      [1, 2, 3, 4, 5].map((n) => el("i", { class: n <= e.severity ? "on" : "" })));
    const meta = [el("span", {}, el("b", {}, "Started "), fmtFull(e._start))];
    if (Math.abs(e._rep - e._start) > 30 * 60000) meta.push(el("span", {}, el("b", {}, "Disclosed "), fmtFull(e._rep)));
    if (e.resolved_at) {
      const r = new Date(e.resolved_at);
      meta.push(el("span", {}, el("b", {}, "Resolved "), fmtFull(r) + " (" + dur(e._start, r) + ")"));
    } else if (e.ongoing) {
      meta.push(el("span", {}, el("b", {}, "Duration "), dur(e._start, Date.now()) + " and counting"));
    }
    const targetLine = [e.target, e.detail].filter(Boolean).join(" · ");
    const why = severityWhy(e);
    return el("article", { class: "ev" + (isNew ? " new" : ""), style: "--cat:" + cat.color },
      el("div", { class: "ev-time" }, fmtTime(e._rep), el("small", {}, tzName)),
      el("div", { class: "ev-main" },
        el("div", { class: "ev-tags" },
          el("span", { class: "badge" }, cat.label), pips,
          e.ongoing ? el("span", { class: "ongoing" }, "Ongoing") : null,
          isNew ? el("span", { class: "newtag" }, "NEW") : null),
        el("h3", {}, e.headline),
        targetLine ? el("p", { class: "target" }, targetLine) : null,
        el("div", { class: "reason" }, el("b", {}, "Alleged reason"), e.alleged_cause || "Not yet disclosed",
          e.attributed_to ? el("div", { class: "actor" }, "Attributed to: " + e.attributed_to) : null),
        el("div", { class: "meta" }, meta),
        why,
        sourceList(e.sources || [])));
  }

  const DIM_LABELS = [["reach", "Reach"], ["criticality", "Critical system"], ["impact", "Impact"],
    ["duration", "Duration"], ["coverage", "News coverage"]];
  const DIM_HELP = {
    reach: ["one small org", "one large org or ~1M people", "millions / a sector", "a country or the world"],
    criticality: ["entertainment", "business & consumer apps", "finance, telecom, cloud", "aviation, health, energy, government"],
    impact: ["slowdown", "partial", "main service down / data exposed", "total outage / data stolen / ops halted"],
    duration: ["under an hour", "hours", "about a day", "days"],
    coverage: ["status page only", "1–2 outlets", "3–9 outlets", "10+ outlets"],
  };
  function severityWhy(e) {
    if (!e.scores) return e.severity_note ? el("p", { class: "why-note" }, "Severity " + e.severity + ": " + e.severity_note) : null;
    const rows = DIM_LABELS.map(([k, label]) => {
      const v = Number(e.scores[k] || 0);
      return el("li", {}, el("span", { class: "why-label" }, label),
        el("span", { class: "why-dots", "aria-hidden": "true" }, [0, 1, 2].map((i) => el("i", { class: i < v ? "on" : "" }))),
        el("span", { class: "why-val" }, v + " · " + DIM_HELP[k][v]));
    });
    return el("details", { class: "why" },
      el("summary", {}, "Why severity " + e.severity + "?"),
      el("ul", {}, rows),
      el("p", { class: "why-total" }, "Total " + e.score_total + " of 15 → severity " + e.severity +
        (e.severity_note ? " (" + e.severity_note + ")" : "")));
  }

  const SRC_SHOWN = 5;
  function sourceList(sources) {
    const link = (s) => {
      const safe = /^https?:\/\//i.test(s.url || "") ? s.url : null;
      return safe ? el("a", { href: safe, target: "_blank", rel: "noopener noreferrer" }, s.name + " ↗") : el("span", {}, s.name);
    };
    const box = el("div", { class: "srcs" }, sources.slice(0, SRC_SHOWN).map(link));
    if (sources.length > SRC_SHOWN) {
      const more = el("button", { class: "src-more", type: "button" }, "+" + (sources.length - SRC_SHOWN) + " more sources");
      more.addEventListener("click", () => { more.replaceWith(...sources.slice(SRC_SHOWN).map(link)); });
      box.append(more);
    }
    return box;
  }

  function renderTimeline() {
    const list = filtered();
    const tl = $("timeline");
    if (state.error && !state.events.length) {
      tl.replaceChildren(el("div", { class: "empty" }, "Couldn't load the event feed. Retrying automatically."));
      return;
    }
    if (!list.length) {
      tl.replaceChildren(el("div", { class: "empty" }, state.events.length ? "Nothing matches these filters. Quiet out there… for now." : "No events yet. The first sweep may still be running."));
      return;
    }
    const nodes = [];
    let day = "";
    for (const e of list.slice(0, state.shown)) {
      const d = fmtDay(e._rep);
      if (d !== day) {
        day = d;
        const n = list.filter((x) => fmtDay(x._rep) === d).length;
        nodes.push(el("h2", { class: "day" }, d, el("em", {}, n + (n === 1 ? " event" : " events"))));
      }
      nodes.push(eventCard(e));
    }
    if (list.length > state.shown) {
      const more = el("button", { class: "more", type: "button" }, "Show more (" + (list.length - state.shown) + " left)");
      more.addEventListener("click", () => { state.shown += PAGE; renderTimeline(); });
      nodes.push(more);
    }
    tl.replaceChildren(...nodes);
  }

  function renderSweep() {
    const st = state.status;
    const dot = $("liveDot");
    const gen = st ? new Date(st.generated_at) : null;
    const age = gen ? Date.now() - gen : Infinity;
    dot.className = "live-dot" + (state.error ? " err" : age > 60 * 60000 ? " stale" : "");
    $("sweepText").textContent = state.error ? "Feed unreachable, retrying" : gen ? "Last sweep " + ago(age) : "Waiting for first sweep";
  }

  function renderFooter() {
    const st = state.status;
    if (!st) return;
    const src = Object.entries(st.sources || {});
    $("health").replaceChildren(...src.map(([name, h]) =>
      el("li", { class: h.ok ? "" : "bad", title: h.error || "" }, name + (h.ok ? "" : " — failing"))));
    const ok = src.filter(([, h]) => h.ok).length;
    $("aboutLine").textContent = "Sweeps " + src.length + " sources every 15 minutes (" + ok + " healthy). News triage: " +
      (st.classifier === "claude" ? "Claude (" + st.model + ")" : "keyword heuristics") + ". " + st.event_count + " events on file.";
  }

  function render() {
    renderSweep();
    renderThreat();
    renderStats();
    renderChips();
    renderTimeline();
    renderFooter();
  }

  // Wire up controls
  let tmr;
  $("q").addEventListener("input", () => { clearTimeout(tmr); tmr = setTimeout(() => { state.shown = PAGE; renderTimeline(); }, 120); });
  for (const id of ["range", "sev", "ongoingOnly"]) $(id).addEventListener("change", () => { state.shown = PAGE; renderChips(); renderTimeline(); });

  // Remember the visit so the next one can highlight new incidents.
  window.addEventListener("pagehide", () => store.set("dat:lastVisit", String(Date.now())));
  setTimeout(() => store.set("dat:lastVisit", String(Date.now())), 60000);

  load();
  setInterval(load, REFRESH_MS);
  setInterval(renderSweep, 30000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden && Date.now() - state.loadedAt > 60000) load(); });
})();
