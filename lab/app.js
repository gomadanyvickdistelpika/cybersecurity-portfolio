/* SOC L1 Case Lab — app logic. No build step, no dependencies. */
(function () {
  "use strict";
  const CASES = window.CASES || [];
  const KEY = "soc-l1-case-lab.v1";
  let IN_FRAME = false; try { IN_FRAME = window.self !== window.top; } catch (e) { IN_FRAME = true; }
  const $ = (s, el = document) => el.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  // ---------- storage (per-viewer, may be unavailable) ----------
  let state = {};
  try { state = JSON.parse(localStorage.getItem(KEY) || "{}") || {}; } catch (e) { state = {}; }
  const save = () => { try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) { /* ignore */ } };
  const cs = (id) => (state[id] = state[id] || { seen: [], checks: [], decision: "", cls: "", notes: "", result: null });

  try { const t = localStorage.getItem(KEY + ".theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) {}

  // ---------- sidebar ----------
  const cats = [...new Set(CASES.map((c) => c.category))].sort();
  $("#catFilter").insertAdjacentHTML("beforeend", cats.map((c) => `<option>${esc(c)}</option>`).join(""));

  function matches(c, q, cat) {
    if (cat && c.category !== cat) return false;
    if (!q) return true;
    const hay = [c.id, c.title, c.category, c.subcategory, c.summary, c.entity,
      ...(c.iocs || []).map((i) => i.value), ...(c.mitre || []).map((m) => m.id + " " + m.name)].join(" ").toLowerCase();
    return hay.includes(q.toLowerCase());
  }

  function renderQueue() {
    const q = $("#search").value.trim(), cat = $("#catFilter").value;
    const cur = currentId();
    $("#queue").innerHTML = CASES.map((c, i) => {
      if (!matches(c, q, cat)) return "";
      const r = state[c.id] && state[c.id].result;
      const st = r ? (r.pass ? `<span class="q-state pass" title="Passed">● ${r.score}</span>` : `<span class="q-state fail" title="Review">● ${r.score}</span>`) : "";
      return `<button class="q-item ${c.id === cur ? "active" : ""}" data-id="${c.id}" type="button">
        <span class="q-num">${String(i + 1).padStart(2, "0")}</span>
        <span><div class="q-title">${esc(c.title)}</div><div class="q-sub">${esc(c.category)} / ${esc(c.subcategory)}</div></span>
        ${st}</button>`;
    }).join("") || `<p class="muted">No cases match.</p>`;
    const done = CASES.filter((c) => state[c.id] && state[c.id].result).length;
    const passed = CASES.filter((c) => state[c.id] && state[c.id].result && state[c.id].result.pass).length;
    $("#progressFill").style.width = (done / CASES.length) * 100 + "%";
    $("#progressText").textContent = `${done} of ${CASES.length} cases completed`;
    const scores = CASES.map((c) => state[c.id] && state[c.id].result && state[c.id].result.score).filter((x) => x != null);
    $("#scoreText").textContent = scores.length ? `${passed} passed · average score ${Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)}/100` : "";
  }

  // ---------- routing ----------
  function currentId() {
    const h = decodeURIComponent(location.hash.slice(1));
    return CASES.some((c) => c.id === h) ? h : CASES[0] && CASES[0].id;
  }

  // ---------- case view ----------
  function renderCase() {
    const c = CASES.find((x) => x.id === currentId());
    if (!c) { $("#caseView").innerHTML = "<p>No cases loaded.</p>"; return; }
    const s = cs(c.id);
    const idx = CASES.indexOf(c);

    const iocRows = (c.iocs || []).length
      ? `<table><thead><tr><th>Type</th><th>Value (defanged)</th><th>Note</th></tr></thead><tbody>${c.iocs.map((i) =>
          `<tr><td>${esc(i.type)}</td><td class="mono">${esc(i.value)}</td><td>${esc(i.note || "")}</td></tr>`).join("")}</tbody></table>`
      : `<p class="muted">No external indicators for this case.</p>`;

    const mitre = (c.mitre || []).length
      ? `<div class="chips">${c.mitre.map((m) => `<a class="chip" target="_blank" rel="noopener" href="https://attack.mitre.org/techniques/${m.id.replace(".", "/")}/">
          <b>${esc(m.id)}</b><span>${esc(m.name)}</span><i>${esc(m.tactic)}</i></a>`).join("")}</div>`
      : `<p class="muted">Not an attack technique — operational / hygiene finding.</p>`;

    $("#caseView").innerHTML = `
      <div class="case-head">
        <div>
          <div class="kicker">${esc(c.id)} · ${esc(c.category.toUpperCase())} / ${esc(c.subcategory.toUpperCase())} · CASE ${idx + 1} OF ${CASES.length}</div>
          <h1>${esc(c.title)}</h1>
          <p class="summary">${esc(c.summary)}</p>
        </div>
        <span class="prio ${esc(c.priority)}">${esc(c.priority)} priority</span>
      </div>

      <div class="card"><h2>Ticket overview <small>State: ${s.result ? "Resolved by analyst" : "New"}</small></h2>
        <div class="meta">
          <div><span>Detection source</span>${esc(c.source)}</div>
          <div><span>Affected entity</span>${esc(c.entity)}</div>
          <div><span>Opened</span>${esc(c.opened)}</div>
          <div><span>Assigned to</span>SOC Queue (you)</div>
        </div>
      </div>

      <div class="grid">
        <div>
          <div class="card"><h2>Investigation evidence <small id="seenCount"></small></h2>
            <div class="tabs" role="tablist">${c.evidence.map((e, i) =>
              `<button class="tab" role="tab" data-i="${i}" type="button">${esc(e.tab)}</button>`).join("")}</div>
            <pre id="evBody"></pre>
          </div>

          <div class="card"><h2>KQL hunting query <small>Microsoft Sentinel / Defender XDR</small></h2>
            <div class="code-wrap"><button class="ghost copy" data-copy="kql" type="button">Copy</button><pre id="kql">${esc(c.kql)}</pre></div>
          </div>

          <div class="card"><h2>Indicators of compromise</h2>${iocRows}</div>

          <div class="card"><h2>MITRE ATT&amp;CK mapping</h2>${mitre}</div>

          <div class="card"><h2>Your disposition</h2>
            <p class="muted">Tick what you checked, choose a disposition and classification, then write work notes before checking the answer.</p>
            <div class="checklist">${c.checklist.map((item, i) =>
              `<label><input type="checkbox" data-check="${i}" ${s.checks.includes(i) ? "checked" : ""}> ${esc(item)}</label>`).join("")}</div>
            <div class="choice-row">
              <button class="choice" data-decision="resolve" aria-pressed="${s.decision === "resolve"}" type="button"><b>Resolve at L1</b><span>Contain within runbook, document and close</span></button>
              <button class="choice" data-decision="escalate" aria-pressed="${s.decision === "escalate"}" type="button"><b>Escalate to L2 / IR</b><span>Contain what you can and hand off</span></button>
            </div>
            <label class="field" for="cls">Classification</label>
            <select id="cls" class="full">
              <option value="">Choose…</option>
              ${["True positive", "Benign true positive", "False positive"].map((o) => `<option ${s.cls === o ? "selected" : ""}>${o}</option>`).join("")}
            </select>
            <label class="field" for="notes">Work notes</label>
            <textarea id="notes" placeholder="What did you check? What did you find? What did you do? Why close or escalate?">${esc(s.notes)}</textarea>
            <div class="actions">
              <button class="primary" id="checkBtn" type="button">Check decision</button>
              <button class="ghost" id="modelBtn" type="button">Show model ticket</button>
              <button class="ghost" id="copyTicketBtn" type="button">Copy ticket (Markdown)</button>
              ${IN_FRAME ? "" : `<button class="ghost" id="exportBtn" type="button">Download ticket (.md)</button>`}
              ${idx < CASES.length - 1 ? `<a class="ghost" href="#${CASES[idx + 1].id}" style="text-decoration:none">Next case →</a>` : ""}
            </div>
            <div id="result"></div>
            <div id="model" class="result model hidden"></div>
          </div>
        </div>

        <div>
          <div class="card"><h2>L1 runbook</h2><ol class="runbook">${c.runbook.map((r) => `<li>${esc(r)}</li>`).join("")}</ol></div>
          <div class="card"><h2>Knowledge articles</h2>
            <div class="kb-item"><div class="tag">Simulated company KB</div>Internal KB ${esc(c.kb.id)} — ${esc(c.kb.title)}</div>
            ${(c.refs || []).map((r) => `<div class="kb-item"><div class="tag">Official reference ↗</div><a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.label)}</a></div>`).join("")}
            <p class="muted">Internal KB IDs are fictional. External links are public guidance.</p>
          </div>
        </div>
      </div>`;

    // evidence tabs
    const showTab = (i) => {
      document.querySelectorAll(".tab").forEach((t) => t.setAttribute("aria-selected", t.dataset.i == i));
      $("#evBody").textContent = c.evidence[i].body;
      if (!s.seen.includes(i)) { s.seen.push(i); save(); }
      document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("seen", s.seen.includes(+t.dataset.i)));
      $("#seenCount").textContent = `${s.seen.length}/${c.evidence.length} reviewed`;
    };
    document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => showTab(+t.dataset.i)));
    showTab(0);

    // inputs
    document.querySelectorAll("[data-check]").forEach((cb) => cb.addEventListener("change", () => {
      const i = +cb.dataset.check;
      s.checks = cb.checked ? [...new Set([...s.checks, i])] : s.checks.filter((x) => x !== i);
      save();
    }));
    document.querySelectorAll("[data-decision]").forEach((b) => b.addEventListener("click", () => {
      s.decision = b.dataset.decision; save();
      document.querySelectorAll("[data-decision]").forEach((x) => x.setAttribute("aria-pressed", x === b));
    }));
    $("#cls").addEventListener("change", (e) => { s.cls = e.target.value; save(); });
    $("#notes").addEventListener("input", (e) => { s.notes = e.target.value; save(); });

    $("#checkBtn").addEventListener("click", () => grade(c, s));
    $("#modelBtn").addEventListener("click", () => showModel(c));
    if ($("#exportBtn")) $("#exportBtn").addEventListener("click", () => exportTicket(c, s));
    $("#copyTicketBtn").addEventListener("click", (e) => copyText(ticketMd(c, s), e.target, "Copy ticket (Markdown)"));
    $("[data-copy]").addEventListener("click", (e) => {
      const txt = c.kql;
      const done = () => { e.target.textContent = "Copied"; setTimeout(() => (e.target.textContent = "Copy"), 1200); };
      if (navigator.clipboard) navigator.clipboard.writeText(txt).then(done, () => {});
    });

    if (s.result) renderResult(c, s.result);
    renderQueue();
    window.scrollTo(0, 0);
  }

  function grade(c, s) {
    const msgs = [];
    if (!s.decision) msgs.push("choose a disposition");
    if (!s.cls) msgs.push("choose a classification");
    if ((s.notes || "").trim().length < 40) msgs.push("write at least a few lines of work notes");
    if (msgs.length) {
      $("#result").innerHTML = `<div class="result fail"><h3>Not yet</h3>Please ${msgs.join(", ")}.</div>`;
      return;
    }
    const decisionOk = s.decision === c.answer;
    const clsOk = s.cls === c.classification;
    const checkPts = Math.round((s.checks.length / c.checklist.length) * 30);
    const evidencePts = s.seen.length === c.evidence.length ? 0 : -5; // small penalty for skipping evidence
    const score = Math.max(0, (decisionOk ? 50 : 0) + (clsOk ? 20 : 0) + checkPts + evidencePts);
    const pass = decisionOk && score >= 70;
    s.result = { score, pass, decisionOk, clsOk, at: new Date().toISOString() };
    save();
    renderResult(c, s.result);
    renderQueue();
  }

  function renderResult(c, r) {
    const s = cs(c.id);
    const missed = c.checklist.filter((_, i) => !s.checks.includes(i));
    $("#result").innerHTML = `<div class="result ${r.pass ? "pass" : "fail"}">
      <h3>${r.pass ? "Pass" : "Review this one"} — ${r.score}/100</h3>
      <div>Disposition: ${r.decisionOk ? "✓ correct" : "✗ expected <b>" + (c.answer === "resolve" ? "Resolve at L1" : "Escalate") + "</b>"} ·
      Classification: ${r.clsOk ? "✓ correct" : "✗ expected <b>" + esc(c.classification) + "</b>"}</div>
      <p style="margin:6px 0 0">${esc(c.rationale)}</p>
      ${missed.length ? `<p class="muted" style="margin:6px 0 0">Steps you did not tick: ${missed.map(esc).join("; ")}.</p>` : ""}
    </div>`;
  }

  function showModel(c) {
    const m = c.model, box = $("#model");
    box.classList.toggle("hidden");
    box.innerHTML = `<h3>Model ticket documentation</h3><dl>
      <dt>Short description</dt><dd>${esc(m.short)}</dd>
      <dt>Disposition</dt><dd>${c.answer === "resolve" ? "Resolved at L1" : "Escalated to L2 / IR"}</dd>
      <dt>Classification</dt><dd>${esc(c.classification)}</dd>
      <dt>Investigation</dt><dd>${esc(m.investigation)}</dd>
      <dt>Actions</dt><dd>${esc(m.actions)}</dd>
      <dt>Next step</dt><dd>${esc(m.next)}</dd></dl>`;
  }

  function copyText(txt, btn, label) {
    const ok = () => { btn.textContent = "Copied"; setTimeout(() => (btn.textContent = label), 1400); };
    const fallback = () => {
      const ta = document.createElement("textarea"); ta.value = txt; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); ok(); } catch (err) { btn.textContent = "Select and copy manually"; }
      ta.remove();
    };
    try { navigator.clipboard.writeText(txt).then(ok, fallback); } catch (err) { fallback(); }
  }

  function exportTicket(c, s) {
    const md = ticketMd(c, s);
    const blob = new Blob([md], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${c.id}-ticket.md`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  function ticketMd(c, s) {
    return `# ${c.id} — ${c.title}

| Field | Value |
|---|---|
| Category | ${c.category} / ${c.subcategory} |
| Priority | ${c.priority} |
| Source | ${c.source} |
| Entity | ${c.entity} |
| Opened | ${c.opened} |
| Analyst disposition | ${s.decision ? (s.decision === "resolve" ? "Resolved at L1" : "Escalated to L2 / IR") : "—"} |
| Classification | ${s.cls || "—"} |
| Lab score | ${s.result ? s.result.score + "/100" : "not checked"} |

## Summary
${c.summary}

## Checks completed
${c.checklist.map((x, i) => `- [${s.checks.includes(i) ? "x" : " "}] ${x}`).join("\n")}

## Indicators (defanged)
${(c.iocs || []).length ? c.iocs.map((i) => `- ${i.type}: \`${i.value}\`${i.note ? " — " + i.note : ""}`).join("\n") : "- None"}

## MITRE ATT&CK
${(c.mitre || []).length ? c.mitre.map((m) => `- ${m.id} ${m.name} (${m.tactic})`).join("\n") : "- N/A"}

## Hunting query
\`\`\`kql
${c.kql}
\`\`\`

## Analyst work notes
${s.notes || "_No notes written._"}

---
_Fictional training case from SOC L1 Case Lab._
`;
  }

  // ---------- events ----------
  $("#queue").addEventListener("click", (e) => {
    const b = e.target.closest("[data-id]"); if (!b) return;
    location.hash = b.dataset.id;
    $("#sidebar").classList.remove("open");
  });
  $("#search").addEventListener("input", renderQueue);
  $("#catFilter").addEventListener("change", renderQueue);
  $("#menuBtn").addEventListener("click", () => $("#sidebar").classList.toggle("open"));
  let resetArmed = null;
  $("#resetBtn").addEventListener("click", (e) => {
    if (!resetArmed) {
      e.target.textContent = "Click again to clear";
      resetArmed = setTimeout(() => { resetArmed = null; e.target.textContent = "Reset progress"; }, 4000);
      return;
    }
    clearTimeout(resetArmed); resetArmed = null; e.target.textContent = "Reset progress";
    state = {}; save(); renderCase();
  });
  $("#themeBtn").addEventListener("click", () => {
    const root = document.documentElement;
    const cur = root.dataset.theme || (window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
    const next = cur === "light" ? "dark" : "light";
    root.dataset.theme = next;
    try { localStorage.setItem(KEY + ".theme", next); } catch (e) {}
  });
  window.addEventListener("hashchange", renderCase);
  renderCase();
})();
