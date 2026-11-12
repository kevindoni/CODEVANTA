"""Self-contained HTML dashboard for the local CODEVANTA web UI.

The page is a single string with inline CSS and JavaScript and **zero external
references**: no CDN, no font, no image, no ``http://``/``https://`` URL. That
keeps the dashboard usable offline (the whole point of a local, read-only
binary-analysis tool) and makes it trivially testable.

Security posture of the generated page:

* Every API response is rendered with ``textContent`` (plus ``textContent`` on
  every cell the table builder creates), so a hostile binary cannot inject
  markup through a symbol name, a string literal or an error message.
* The only network target is the same-origin ``/api/*`` route table served by
  :mod:`codevanta.gui.server`; the page never contacts a third party.
* Nothing is uploaded: the file paths typed into the form are resolved by the
  server process, and analysis is strictly read-only.

:func:`render_dashboard_html` is the only public entry point.
"""

from __future__ import annotations

__all__ = ["render_dashboard_html"]

_STYLE = """
:root {
  color-scheme: dark;
  --bg: #0a0c10;
  --card: #10141b;
  --card-2: #161b25;
  --line: #1e2634;
  --line-2: #2c3648;
  --ink: #dde6f2;
  --mut: #9aa8bc;
  --dim: #66748c;
  --acc: #2dd4bf;
  --acc-strong: #14b8a6;
  --acc-bg: rgba(45, 212, 191, 0.09);
  --err: #f87171;
  --ok: #4ade80;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
          "Helvetica Neue", Arial, sans-serif;
  --radius: 10px;
}
* { box-sizing: border-box; }
html { height: 100%; }
body {
  margin: 0;
  min-height: 100%;
  padding: 0 0 56px;
  font-family: var(--sans);
  font-size: 14px;
  line-height: 1.5;
  background:
    radial-gradient(1100px 480px at 85% -10%, rgba(45, 212, 191, 0.07), transparent 60%),
    radial-gradient(900px 420px at -10% 0%, rgba(99, 102, 241, 0.05), transparent 55%),
    var(--bg);
  color: var(--ink);
}
.wrap { max-width: 1240px; margin: 0 auto; padding: 0 28px; }

/* ---- top bar ---------------------------------------------------------- */
.topbar {
  border-bottom: 1px solid var(--line);
  background: rgba(10, 12, 16, 0.82);
  position: sticky; top: 0; z-index: 5;
}
.topbar .wrap {
  display: flex; align-items: center; gap: 16px;
  padding-top: 14px; padding-bottom: 14px;
}
.mark {
  width: 38px; height: 38px; flex: none;
  display: grid; place-items: center;
  border-radius: 10px;
  border: 1px solid rgba(45, 212, 191, 0.55);
  background: linear-gradient(160deg, rgba(45, 212, 191, 0.16), rgba(45, 212, 191, 0.03));
  color: var(--acc);
  font: 700 13px/1 var(--mono);
  letter-spacing: 0.04em;
}
.brand h1 {
  margin: 0;
  font-size: 17px; font-weight: 700; letter-spacing: 0.14em;
  text-transform: uppercase; color: var(--ink);
}
.brand h1 em {
  font-style: normal; color: var(--acc);
}
.brand p {
  margin: 2px 0 0;
  font-size: 12px; color: var(--dim);
}
.meta { margin-left: auto; display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
.pill {
  display: inline-flex; align-items: center; gap: 7px;
  padding: 5px 11px;
  border: 1px solid var(--line-2);
  border-radius: 999px;
  font-size: 11px; font-weight: 600; letter-spacing: 0.05em;
  text-transform: uppercase; color: var(--dim);
  white-space: nowrap;
}
.pill .dot {
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--ok);
  box-shadow: 0 0 6px rgba(74, 222, 128, 0.8);
}
.pill.secure .dot { background: var(--acc); box-shadow: 0 0 6px rgba(45, 212, 191, 0.8); }

/* ---- cards ------------------------------------------------------------ */
main.wrap { padding-top: 24px; display: grid; gap: 16px; }
.card {
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: linear-gradient(180deg, var(--card-2), var(--card));
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.03);
  padding: 20px 22px 22px;
}
.card-head {
  display: flex; align-items: baseline; gap: 12px;
  margin: 0 0 16px;
}
.card-head h2 {
  margin: 0;
  font-size: 13px; font-weight: 700; letter-spacing: 0.12em;
  text-transform: uppercase; color: var(--mut);
}
.card-head .hint { margin: 0; font-size: 12px; color: #7c8aa0; }

/* ---- forms ------------------------------------------------------------ */
label {
  display: block; margin: 0 0 6px;
  font-size: 11px; font-weight: 600; letter-spacing: 0.07em;
  text-transform: uppercase; color: var(--mut);
}
input, select {
  width: 100%;
  height: 38px;
  padding: 0 11px;
  border: 1px solid var(--line-2);
  border-radius: 8px;
  background: #0b0e13;
  color: var(--ink);
  font: 500 13px/1 var(--sans);
  transition: border-color 0.15s, box-shadow 0.15s;
}
input.mono, .mono input { font-family: var(--mono); }
input:focus, select:focus {
  outline: none;
  border-color: var(--acc);
  box-shadow: 0 0 0 3px rgba(45, 212, 191, 0.16);
}
input::placeholder { color: #46536b; }
.selwrap { position: relative; }
.selwrap select { appearance: none; padding-right: 32px; cursor: pointer; }
.selwrap::after {
  content: "";
  position: absolute; right: 13px; top: 50%;
  width: 7px; height: 7px;
  border-right: 1.5px solid var(--dim);
  border-bottom: 1.5px solid var(--dim);
  transform: translateY(-70%) rotate(45deg);
  pointer-events: none;
}

/* ---- hero path row ---------------------------------------------------- */
.path-row { display: flex; gap: 12px; align-items: flex-end; margin-bottom: 14px; }
.path-row .grow { flex: 1; }
#path {
  height: 46px;
  font-size: 14px;
  border-color: var(--line-2);
}
.path-row kbd {
  display: inline-block;
  margin-left: 8px;
  padding: 2px 6px;
  border: 1px solid var(--line-2);
  border-bottom-width: 2px;
  border-radius: 5px;
  background: #0b0e13;
  font: 600 10px/1.4 var(--mono);
  color: var(--dim);
}

/* ---- option grids ------------------------------------------------------ */
.options {
  border: 1px dashed var(--line);
  border-radius: 8px;
  padding: 14px 14px 2px;
  margin: 0 0 16px;
}
.options legend {
  padding: 0 6px;
  font-size: 10px; font-weight: 700; letter-spacing: 0.12em;
  text-transform: uppercase; color: var(--dim);
}
.grid-opts {
  display: grid; gap: 12px;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
}
.grid-opts > div { min-width: 0; }

/* ---- buttons ----------------------------------------------------------- */
.group-label {
  margin: 0 0 8px;
  font-size: 10px; font-weight: 700; letter-spacing: 0.12em;
  text-transform: uppercase; color: var(--dim);
}
.verbs {
  display: grid; gap: 8px;
  grid-template-columns: repeat(auto-fit, minmax(118px, 1fr));
}
button {
  height: 40px;
  padding: 0 14px;
  border: 1px solid var(--line-2);
  border-radius: 8px;
  background: transparent;
  color: var(--mut);
  font: 650 12px/1 var(--sans);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  cursor: pointer;
  transition: color 0.15s, border-color 0.15s, background 0.15s, transform 0.06s;
}
button:hover {
  color: var(--acc);
  border-color: rgba(45, 212, 191, 0.55);
  background: var(--acc-bg);
}
button:active { transform: translateY(1px); }
button.primary {
  border-color: transparent;
  background: linear-gradient(180deg, var(--acc), var(--acc-strong));
  color: #052e28;
  font-weight: 750;
}
button.primary:hover {
  color: #052e28;
  filter: brightness(1.08);
  background: linear-gradient(180deg, var(--acc), var(--acc-strong));
}
.row-2col {
  display: grid; gap: 12px;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
}

/* ---- result ------------------------------------------------------------ */
.card.result { display: grid; gap: 0; }
.result-head {
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
  margin: 0 0 14px;
}
.result-head h2 {
  margin: 0;
  font-size: 13px; font-weight: 700; letter-spacing: 0.12em;
  text-transform: uppercase; color: var(--mut);
}
.status {
  font: 600 11px/1 var(--mono);
  color: var(--dim);
  padding: 5px 10px;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: #0b0e13;
  letter-spacing: 0.02em;
  text-transform: none;
}
.status.error { color: var(--err); border-color: rgba(248, 113, 113, 0.4); }
.table-wrap {
  overflow: auto;
  max-height: 56vh;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #0b0e13;
}
table#tbl { width: 100%; border-collapse: collapse; font-size: 12.5px; }
table#tbl th, table#tbl td {
  padding: 8px 12px;
  border-bottom: 1px solid var(--line);
  text-align: left; vertical-align: top;
  font-family: var(--mono);
}
table#tbl tbody tr:last-child td { border-bottom: none; }
table#tbl tbody tr:hover td { background: rgba(45, 212, 191, 0.04); }
table#tbl th {
  position: sticky; top: 0; z-index: 1;
  color: var(--dim);
  font: 700 10px/1.2 var(--sans);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  background: var(--card-2);
  border-bottom: 1px solid var(--line-2);
}
td.conf {
  font: 600 10px/1 var(--sans);
  letter-spacing: 0.06em;
  text-transform: uppercase;
}
td.conf::before {
  content: "";
  display: inline-block;
  width: 7px; height: 7px; margin-right: 6px;
  border-radius: 50%;
  vertical-align: baseline;
}
td.conf-high { color: var(--ok); }
td.conf-high::before { background: var(--ok); box-shadow: 0 0 5px rgba(74, 222, 128, 0.7); }
td.conf-medium { color: #fbbf24; }
td.conf-medium::before { background: #fbbf24; box-shadow: 0 0 5px rgba(251, 191, 36, 0.6); }
td.conf-low { color: var(--err); }
td.conf-low::before { background: var(--err); box-shadow: 0 0 5px rgba(248, 113, 113, 0.6); }
details.raw {
  margin-top: 12px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #0b0e13;
}
details.raw summary {
  cursor: pointer;
  padding: 9px 14px;
  font-size: 11px; font-weight: 700; letter-spacing: 0.1em;
  text-transform: uppercase; color: var(--dim);
  user-select: none;
  list-style: none;
  display: flex; align-items: center; gap: 8px;
}
details.raw summary::before {
  content: "";
  width: 0; height: 0;
  border-left: 5px solid var(--dim);
  border-top: 4px solid transparent;
  border-bottom: 4px solid transparent;
  transition: transform 0.15s;
}
details.raw[open] summary::before { transform: rotate(90deg); }
details.raw summary:hover { color: var(--mut); }
pre#out {
  margin: 0;
  padding: 14px;
  max-height: 340px;
  overflow: auto;
  border-top: 1px solid var(--line);
  font: 400 12px/1.55 var(--mono);
  color: #b9c5d6;
  white-space: pre-wrap;
  word-break: break-word;
}

/* ---- responsive -------------------------------------------------------- */
@media (max-width: 760px) {
  .topbar .wrap { flex-wrap: wrap; }
  .meta { margin-left: 0; }
  .path-row { flex-direction: column; align-items: stretch; }
}
"""

_BODY = """
<div class="topbar">
  <div class="wrap">
    <div class="mark">CV</div>
    <div class="brand">
      <h1>code<em>vanta</em></h1>
      <p>Advanced code intelligence &middot; decode, analyze, understand</p>
    </div>
    <div class="meta">
      <span class="pill"><span class="dot"></span>read-only</span>
      <span class="pill secure"><span class="dot"></span>local &middot; static</span>
    </div>
  </div>
</div>
<main class="wrap">
  <section class="card">
    <div class="card-head">
      <h2>Analyze a binary</h2>
      <p class="hint">files are parsed, never executed or modified &mdash; nothing leaves this machine</p>
    </div>
    <div class="path-row">
      <div class="grow mono">
        <label for="path">Binary path <kbd>Enter</kbd> runs Info</label>
        <input id="path" type="text" spellcheck="false" autocomplete="off"
               placeholder="absolute path to a PE, ELF or Mach-O file">
      </div>
    </div>
    <fieldset class="options">
      <legend>Options</legend>
      <div class="grid-opts">
        <div>
          <label for="address">Address (hex or decimal)</label>
          <input id="address" type="text" spellcheck="false" autocomplete="off" value="0x401000">
        </div>
        <div>
          <label for="limit">Limit</label>
          <input id="limit" type="number" min="0" max="200000" step="1" value="100">
        </div>
        <div>
          <label for="min_length">Strings &middot; min length</label>
          <input id="min_length" type="number" min="1" max="200000" step="1" value="4">
        </div>
        <div>
          <label for="max_fields">Struct &middot; max fields</label>
          <input id="max_fields" type="number" min="1" max="512" step="1" value="64">
        </div>
        <div>
          <label for="limit_edges">Callgraph &middot; max edges</label>
          <input id="limit_edges" type="number" min="1" max="200000" step="1" value="5000">
        </div>
        <div>
          <label for="traversal">CFG traversal</label>
          <div class="selwrap">
            <select id="traversal">
              <option value="linear">linear</option>
              <option value="recursive">recursive</option>
            </select>
          </div>
        </div>
        <div>
          <label for="include_stack">Struct &middot; include stack</label>
          <div class="selwrap">
            <select id="include_stack">
              <option value="0">no</option>
              <option value="1">yes</option>
            </select>
          </div>
        </div>
      </div>
    </fieldset>
    <p class="group-label">Run analysis</p>
    <div class="grid-opts" style="margin-bottom:14px">
      <div>
        <label for="backend">Decompile &middot; backend</label>
        <div class="selwrap">
          <select id="backend">
            <option value="auto">auto</option>
            <option value="native">native</option>
            <option value="angr">angr</option>
            <option value="ghidra">ghidra</option>
          </select>
        </div>
      </div>
    </div>
    <div class="verbs">
      <button type="button" data-action="info">Info</button>
      <button type="button" data-action="functions">Functions</button>
      <button type="button" data-action="strings">Strings</button>
      <button type="button" data-action="xrefs">Xrefs</button>
      <button type="button" data-action="cfg">CFG</button>
      <button type="button" data-action="struct">Struct</button>
      <button type="button" data-action="callgraph">Callgraph</button>
      <button type="button" data-action="decompile">Decompile</button>
    </div>
  </section>

  <section class="card">
    <div class="card-head">
      <h2>Diff two binaries</h2>
      <p class="hint">pair every function across two builds of the same program</p>
    </div>
    <div class="row-2col">
      <div class="mono">
        <label for="left">Baseline</label>
        <input id="left" type="text" spellcheck="false" autocomplete="off" placeholder="absolute path">
      </div>
      <div class="mono">
        <label for="right">Candidate</label>
        <input id="right" type="text" spellcheck="false" autocomplete="off" placeholder="absolute path">
      </div>
    </div>
    <div class="grid-opts" style="margin-top:12px">
      <div>
        <label for="semantic">Mode</label>
        <div class="selwrap">
          <select id="semantic">
            <option value="0">structural</option>
            <option value="1">semantic</option>
          </select>
        </div>
      </div>
      <div>
        <label for="threshold" title="0-1 similarity cutoff: 0 pairs everything, 1 demands identical shapes">Semantic threshold</label>
        <input id="threshold" type="number" min="0" max="1" step="0.05" value="0.5">
      </div>
    </div>
    <div class="verbs" style="margin-top:14px; grid-template-columns: minmax(0, 200px)">
      <button type="button" data-action="diff" class="primary">Diff</button>
    </div>
  </section>

  <section class="card result">
    <div class="result-head">
      <h2>Result</h2>
      <span class="status" id="status">idle</span>
    </div>
    <div class="table-wrap">
      <table id="tbl">
        <thead><tr></tr></thead>
        <tbody></tbody>
      </table>
    </div>
    <details class="raw" open>
      <summary>Raw JSON</summary>
      <pre id="out">No request yet. Point the path field at a binary and pick an analysis above.</pre>
    </details>
  </section>
</main>
"""


_SCRIPT = """
(function () {
  "use strict";

  var ENDPOINTS = {
    info: "/api/info",
    functions: "/api/functions",
    strings: "/api/strings",
    xrefs: "/api/xrefs",
    cfg: "/api/cfg",
    struct: "/api/struct",
    callgraph: "/api/callgraph",
    diff: "/api/diff",
    decompile: "/api/decompile"
  };

  var MAX_TABLE_ROWS = 200;
  var MAX_TABLE_COLUMNS = 8;
  var MAX_CELL_CHARS = 120;

  function byId(id) {
    return document.getElementById(id);
  }

  function fieldValue(id) {
    var element = byId(id);
    if (!element || typeof element.value !== "string") {
      return "";
    }
    return element.value.trim();
  }

  function setStatus(message, isError) {
    var element = byId("status");
    if (!element) {
      return;
    }
    element.textContent = message;
    element.className = isError ? "status error" : "status";
  }

  function addParam(parts, key, value) {
    if (value === null || value === undefined || value === "") {
      return;
    }
    parts.push(encodeURIComponent(key) + "=" + encodeURIComponent(value));
  }

  function queryFor(action) {
    var parts = [];
    if (action === "diff") {
      addParam(parts, "left", fieldValue("left"));
      addParam(parts, "right", fieldValue("right"));
      addParam(parts, "semantic", fieldValue("semantic") || "0");
      addParam(parts, "threshold", fieldValue("threshold"));
      return parts;
    }
    addParam(parts, "path", fieldValue("path"));
    if (action === "info") {
      addParam(parts, "max_functions", fieldValue("limit"));
    } else if (action === "functions" || action === "xrefs") {
      addParam(parts, "limit", fieldValue("limit"));
    } else if (action === "strings") {
      addParam(parts, "limit", fieldValue("limit"));
      addParam(parts, "min_length", fieldValue("min_length"));
    } else if (action === "cfg") {
      addParam(parts, "address", fieldValue("address"));
      addParam(parts, "traversal", fieldValue("traversal") || "linear");
    } else if (action === "struct") {
      addParam(parts, "address", fieldValue("address"));
      addParam(parts, "include_stack", fieldValue("include_stack") || "0");
      addParam(parts, "max_fields", fieldValue("max_fields"));
    } else if (action === "callgraph") {
      addParam(parts, "limit_functions", fieldValue("limit"));
      addParam(parts, "limit_edges", fieldValue("limit_edges"));
    } else if (action === "decompile") {
      addParam(parts, "address", fieldValue("address"));
      addParam(parts, "backend", fieldValue("backend") || "auto");
    }
    return parts;
  }

  function isRowList(value) {
    return Object.prototype.toString.call(value) === "[object Array]" && value.length > 0;
  }

  function pickRows(data) {
    if (!data || typeof data !== "object") {
      return [];
    }
    var keys = [
      "items",
      "functions",
      "xrefs",
      "strings",
      "blocks",
      "fields",
      "nodes",
      "sections",
      "array_groups",
      "warnings"
    ];
    var index;
    for (index = 0; index < keys.length; index += 1) {
      if (isRowList(data[keys[index]])) {
        return data[keys[index]];
      }
    }
    return [];
  }

  function cellText(value) {
    if (value === null || value === undefined) {
      return "";
    }
    if (typeof value === "object") {
      var encoded;
      try {
        encoded = JSON.stringify(value);
      } catch (error) {
        encoded = String(error);
      }
      if (encoded.length > MAX_CELL_CHARS) {
        return encoded.slice(0, MAX_CELL_CHARS - 3) + "...";
      }
      return encoded;
    }
    return String(value);
  }

  function columnsFor(rows) {
    var columns = [];
    var sample = rows.slice(0, 25);
    var index;
    for (index = 0; index < sample.length; index += 1) {
      var row = sample[index];
      if (!row || typeof row !== "object") {
        continue;
      }
      var names = Object.keys(row);
      var position;
      for (position = 0; position < names.length; position += 1) {
        if (columns.length >= MAX_TABLE_COLUMNS) {
          break;
        }
        if (columns.indexOf(names[position]) === -1) {
          columns.push(names[position]);
        }
      }
    }
    return columns;
  }

  function renderTable(rows) {
    var table = byId("tbl");
    if (!table || !table.tHead || !table.tBodies.length) {
      return;
    }
    var head = table.tHead.rows[0];
    var body = table.tBodies[0];
    while (head.cells.length > 0) {
      head.deleteCell(-1);
    }
    while (body.firstChild) {
      body.removeChild(body.firstChild);
    }
    if (!rows || !rows.length) {
      return;
    }
    var columns = columnsFor(rows);
    if (!columns.length) {
      columns = ["value"];
    }
    columns.forEach(function (name) {
      var cell = document.createElement("th");
      cell.textContent = name;
      head.appendChild(cell);
    });
    rows.slice(0, MAX_TABLE_ROWS).forEach(function (row) {
      var tr = document.createElement("tr");
      columns.forEach(function (name) {
        var td = document.createElement("td");
        if (row && typeof row === "object") {
          td.textContent = cellText(row[name]);
        } else {
          td.textContent = cellText(row);
        }
        if (name === "confidence" || name === "confidence_level") {
          var level = String(td.textContent).toLowerCase();
          if (level.indexOf("certain") !== -1 || level.indexOf("high") !== -1) {
            td.className = "conf conf-high";
          } else if (level.indexOf("medium") !== -1) {
            td.className = "conf conf-medium";
          } else if (level !== "") {
            td.className = "conf conf-low";
          }
        }
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
  }

  function showPayload(payload) {
    var output = byId("out");
    if (!output) {
      return;
    }
    try {
      output.textContent = JSON.stringify(payload, null, 2);
    } catch (error) {
      output.textContent = String(payload);
    }
  }

  function run(action) {
    var endpoint = ENDPOINTS[action];
    if (!endpoint) {
      setStatus("unknown action " + action, true);
      return;
    }
    var parts = queryFor(action);
    var url = endpoint + (parts.length ? "?" + parts.join("&") : "");
    setStatus("requesting " + endpoint, false);
    fetch(url, { headers: { Accept: "application/json" } })
      .then(function (response) {
        return response
          .json()
          .then(function (data) {
            return { ok: response.ok, status: response.status, data: data };
          })
          .catch(function () {
            return { ok: response.ok, status: response.status, data: { error: "invalid JSON" } };
          });
      })
      .then(function (result) {
        showPayload(result.data);
        if (result.ok) {
          var rows = pickRows(result.data);
          renderTable(rows);
          var shown = Math.min(rows.length, MAX_TABLE_ROWS);
          var summary = "HTTP " + result.status + (rows.length ? " · " + shown + (rows.length > MAX_TABLE_ROWS ? " of " + rows.length : "") + " rows" : "");
          setStatus(summary, false);
          var resultCard = document.querySelector(".card.result");
          if (resultCard && resultCard.scrollIntoView) {
            resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
          }
        } else {
          var detail = result.data && result.data.error ? result.data.error : "request failed";
          setStatus("HTTP " + result.status + " " + detail, true);
          renderTable([]);
        }
      })
      .catch(function (error) {
        showPayload({ error: String(error) });
        setStatus("request failed", true);
        renderTable([]);
      });
  }

  var buttons = document.querySelectorAll("button[data-action]");
  Array.prototype.forEach.call(buttons, function (button) {
    button.addEventListener("click", function (event) {
      run(event.currentTarget.getAttribute("data-action"));
    });
  });

  var pathInput = byId("path");
  if (pathInput) {
    pathInput.addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        run("info");
      }
    });
  }
})();


"""

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>__STYLE__</style>
</head>
<body>
__BODY__
<script>__SCRIPT__</script>
</body>
</html>
"""


def _escape_html(text: str) -> str:
    """Escape ``text`` for safe interpolation into HTML text and attributes."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def render_dashboard_html(title: str = "CODEVANTA") -> str:
    """Render the single-page dashboard as one self-contained HTML string.

    The document inlines its CSS and JavaScript, references no external
    resource (no CDN, no font, no image, no absolute URL) and talks only to the
    same-origin ``/api/*`` routes of :mod:`codevanta.gui.server`. Results are
    written with ``textContent``, so analysed data is never interpreted as
    markup.

    Args:
        title: Page title, used for both ``<title>`` and the heading. HTML
            special characters are escaped; a blank title falls back to
            ``"CODEVANTA"``.

    Returns:
        The complete HTML document.

    Raises:
        TypeError: If ``title`` is not a string.
    """
    if not isinstance(title, str):
        raise TypeError(f"title must be a string, got {type(title).__name__}")
    page = (
        _TEMPLATE.replace("__STYLE__", _STYLE)
        .replace("__BODY__", _BODY)
        .replace("__SCRIPT__", _SCRIPT)
    )
    # Applied last so a title that happens to look like a placeholder cannot be
    # expanded by a later substitution.
    return page.replace("__TITLE__", _escape_html(title.strip() or "CODEVANTA"))
