"""Self-contained HTML dashboard for the local CODEVANTA web UI.

The page is a single string with inline CSS and JavaScript and **zero external
references**: no CDN, no font, no image, no ``http://``/``https://`` URL. That
keeps the dashboard usable offline (the whole point of a local, read-only
binary-analysis tool) and makes it trivially testable.

Security posture of the generated page:

* Every API response is rendered with ``textContent`` (plus ``textContent`` on
  every cell the table and summary builders create), so a hostile binary
  cannot inject markup through a symbol name, a string literal or an error
  message.
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
  --warn: #fbbf24;
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
.wrap { max-width: 1180px; margin: 0 auto; padding: 0 28px; }
.hidden { display: none !important; }

/* ---- top bar ---------------------------------------------------------- */
.topbar {
  border-bottom: 1px solid var(--line);
  background: rgba(10, 12, 16, 0.85);
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
.brand h1 em { font-style: normal; color: var(--acc); }
.brand p { margin: 2px 0 0; font-size: 12px; color: #7c8aa0; }
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
main.wrap { padding-top: 22px; display: grid; gap: 16px; }
.card {
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: linear-gradient(180deg, var(--card-2), var(--card));
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.03);
  padding: 20px 22px 22px;
}
.card-head { display: flex; align-items: baseline; gap: 12px; margin: 0 0 14px; }
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
.mono input, input.mono { font-family: var(--mono); }
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

/* ---- hero ------------------------------------------------------------- */
.step-tag {
  display: inline-flex; align-items: center; gap: 8px;
  margin: 0 0 10px;
  font-size: 11px; font-weight: 700; letter-spacing: 0.12em;
  text-transform: uppercase; color: var(--acc);
}
.step-tag .n {
  width: 18px; height: 18px; border-radius: 50%;
  display: grid; place-items: center;
  border: 1px solid rgba(45, 212, 191, 0.5);
  font: 700 10px/1 var(--mono);
}
.hero-row { display: flex; gap: 12px; align-items: stretch; }
.hero-row .grow { flex: 1; }
#path { height: 48px; font-size: 14px; }
.hero-row kbd {
  display: inline-block; margin-left: 8px;
  padding: 2px 6px;
  border: 1px solid var(--line-2); border-bottom-width: 2px;
  border-radius: 5px; background: #0b0e13;
  font: 600 10px/1.4 var(--mono); color: var(--dim);
}
.hero-hint { margin: 10px 0 0; font-size: 12px; color: #7c8aa0; }

/* ---- buttons ---------------------------------------------------------- */
button {
  height: 40px;
  padding: 0 16px;
  border: 1px solid var(--line-2);
  border-radius: 8px;
  background: transparent;
  color: var(--mut);
  font: 650 12px/1 var(--sans);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  cursor: pointer;
  white-space: nowrap;
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
button.primary:hover { color: #052e28; filter: brightness(1.08); }
#run-info { height: 48px; padding: 0 22px; font-size: 13px; }

/* ---- explore tools ---------------------------------------------------- */
.tools {
  display: grid; gap: 12px;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
}
.tool {
  display: flex; flex-direction: column; gap: 10px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #0d1118;
  padding: 14px 14px 12px;
}
.tool-top { display: flex; align-items: center; gap: 10px; }
.glyph {
  width: 30px; height: 30px; flex: none;
  display: grid; place-items: center;
  border-radius: 7px;
  border: 1px solid var(--line-2);
  background: #10151d;
  color: var(--acc);
  font: 700 11px/1 var(--mono);
  letter-spacing: 0.02em;
}
.tool-top b { font-size: 14px; font-weight: 650; color: var(--ink); }
.tool .desc { margin: 0; font-size: 12.5px; color: var(--mut); line-height: 1.45; }
.tool-opts { display: grid; gap: 8px; grid-template-columns: 1fr 1fr; }
.tool-opts .full { grid-column: 1 / -1; }
.tool-opts label { font-size: 10px; margin: 0; color: var(--dim); }
.tool-opts input, .tool-opts select { height: 32px; font-size: 12px; }
.tool-opts .single { grid-template-columns: 1fr; }
.tool button { width: 100%; height: 36px; margin-top: 2px; }

/* ---- diff (collapsed secondary task) ----------------------------------- */
details.diffbox { border: 1px dashed var(--line-2); border-radius: var(--radius); background: rgba(13, 17, 24, 0.6); }
details.diffbox > summary {
  cursor: pointer; padding: 14px 18px;
  font-size: 13px; font-weight: 700; letter-spacing: 0.1em;
  text-transform: uppercase; color: var(--mut);
  user-select: none; list-style: none;
  display: flex; align-items: center; gap: 10px;
}
details.diffbox > summary::before {
  content: "";
  width: 0; height: 0;
  border-left: 5px solid var(--dim);
  border-top: 4px solid transparent; border-bottom: 4px solid transparent;
  transition: transform 0.15s;
}
details.diffbox[open] > summary::before { transform: rotate(90deg); }
details.diffbox > summary:hover { color: var(--ink); }
.diffbox-body { padding: 4px 18px 18px; }
.diffgrid { display: grid; gap: 12px; grid-template-columns: 1fr 1fr; }
.diffgrid + .diffgrid { margin-top: 12px; }

/* ---- result ----------------------------------------------------------- */
.card.result { display: grid; gap: 0; }
.result-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; margin: 0 0 14px; }
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

#empty { padding: 26px 8px 10px; text-align: center; }
#empty .big { margin: 0 0 6px; font-size: 16px; font-weight: 650; color: var(--mut); }
#empty p { margin: 0 auto; max-width: 520px; font-size: 13px; color: var(--dim); }

#summary { display: grid; gap: 14px; }
.chips { display: flex; flex-wrap: wrap; gap: 8px; }
.chip {
  display: inline-flex; align-items: baseline; gap: 7px;
  padding: 7px 12px;
  border: 1px solid var(--line-2);
  border-radius: 8px;
  background: #0d1118;
}
.chip .k {
  font-size: 10px; font-weight: 700; letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--dim);
}
.chip .v { font: 600 12.5px/1 var(--mono); color: var(--ink); }
.chip.acc .v { color: var(--acc); }
.kv {
  display: grid; gap: 0;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #0b0e13;
  overflow: hidden;
}
.kv-row {
  display: grid; grid-template-columns: 170px 1fr;
  border-bottom: 1px solid var(--line);
}
.kv-row:last-child { border-bottom: none; }
.kv-row .k {
  padding: 9px 14px;
  font-size: 11px; font-weight: 600; letter-spacing: 0.06em;
  text-transform: uppercase; color: var(--dim);
  background: rgba(22, 27, 37, 0.5);
}
.kv-row .v { padding: 9px 14px; font: 500 12.5px/1.5 var(--mono); color: #c3cedd; word-break: break-all; }
.kv-note { margin: 0; font-size: 12px; color: var(--dim); }
.kv-note b { color: var(--mut); font-weight: 650; }
.kv-note.error { color: var(--err); }

.table-wrap, .session-wrap {
  overflow: auto;
  max-height: 56vh;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #0b0e13;
}
table#tbl, table#session-tbl { width: 100%; border-collapse: collapse; font-size: 12.5px; }
table#tbl th, table#tbl td,
table#session-tbl th, table#session-tbl td {
  padding: 8px 12px;
  border-bottom: 1px solid var(--line);
  text-align: left; vertical-align: top;
  font-family: var(--mono);
}
table#tbl tbody tr:last-child td,
table#session-tbl tbody tr:last-child td { border-bottom: none; }
table#tbl tbody tr:hover td,
table#session-tbl tbody tr:hover td { background: rgba(45, 212, 191, 0.04); }
table#tbl th, table#session-tbl th {
  position: sticky; top: 0; z-index: 1;
  color: var(--dim);
  font: 700 10px/1.2 var(--sans);
  letter-spacing: 0.08em;
  text-transform: uppercase;
  background: var(--card-2);
  border-bottom: 1px solid var(--line-2);
}
td.conf { font: 600 10px/1 var(--sans); letter-spacing: 0.06em; text-transform: uppercase; }
td.conf::before {
  content: "";
  display: inline-block;
  width: 7px; height: 7px; margin-right: 6px;
  border-radius: 50%;
  vertical-align: baseline;
}
td.conf-high { color: var(--ok); }
td.conf-high::before { background: var(--ok); box-shadow: 0 0 5px rgba(74, 222, 128, 0.7); }
td.conf-medium { color: var(--warn); }
td.conf-medium::before { background: var(--warn); box-shadow: 0 0 5px rgba(251, 191, 36, 0.6); }
td.conf-low { color: var(--err); }
td.conf-low::before { background: var(--err); box-shadow: 0 0 5px rgba(248, 113, 113, 0.6); }

#codeview {
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #0b0e13;
  overflow: auto;
  max-height: 60vh;
}
pre#codepre {
  margin: 0;
  padding: 16px 18px;
  font: 400 12.5px/1.6 var(--mono);
  color: #cfe6dc;
  white-space: pre;
}
details.raw { margin-top: 12px; border: 1px solid var(--line); border-radius: 8px; background: #0b0e13; }
details.raw summary {
  cursor: pointer; padding: 9px 14px;
  font-size: 11px; font-weight: 700; letter-spacing: 0.1em;
  text-transform: uppercase; color: var(--dim);
  user-select: none; list-style: none;
  display: flex; align-items: center; gap: 8px;
}
details.raw summary::before {
  content: "";
  width: 0; height: 0;
  border-left: 5px solid var(--dim);
  border-top: 4px solid transparent; border-bottom: 4px solid transparent;
  transition: transform 0.15s;
}
details.raw[open] summary::before { transform: rotate(90deg); }
details.raw summary:hover { color: var(--mut); }
pre#out {
  margin: 0; padding: 14px;
  max-height: 340px; overflow: auto;
  border-top: 1px solid var(--line);
  font: 400 12px/1.55 var(--mono);
  color: #b9c5d6;
  white-space: pre-wrap; word-break: break-word;
}

/* ---- responsive -------------------------------------------------------- */
@media (max-width: 760px) {
  .topbar .wrap { flex-wrap: wrap; }
  .meta { margin-left: 0; }
  .hero-row { flex-direction: column; }
  .diffgrid { grid-template-columns: 1fr; }
}
"""

_BODY = """
<div class="topbar">
  <div class="wrap">
    <div class="mark">CV</div>
    <div class="brand">
      <h1>code<em>vanta</em></h1>
      <p>Look inside any binary &mdash; safely, offline, step by step</p>
    </div>
    <div class="meta">
      <span class="pill"><span class="dot"></span>read-only</span>
      <span class="pill secure"><span class="dot"></span>local &middot; static</span>
    </div>
  </div>
</div>
<main class="wrap">

  <section class="card">
    <p class="step-tag"><span class="n">1</span> Pick a file</p>
    <div class="hero-row">
      <div class="grow mono">
        <label for="path">Binary path <kbd>Enter</kbd></label>
        <input id="path" type="text" spellcheck="false" autocomplete="off"
               placeholder="absolute path &mdash; e.g. a .exe, .dll, .so or Mach-O file">
      </div>
      <div>
        <label style="visibility:hidden">run</label>
        <button type="button" id="run-info" class="primary" data-action="info">Analyze &rsaquo;</button>
      </div>
    </div>
    <p class="hero-hint">
      The file is only read from disk &mdash; never executed, never modified, never uploaded.
      Start with <b>Analyze</b>: you get a plain-language overview, then the views below dig deeper.
    </p>
  </section>

  <section class="card result">
    <div class="result-head">
      <h2>Result</h2>
      <span class="status" id="status">idle</span>
    </div>
    <div id="empty">
      <p class="big">Nothing loaded yet</p>
      <p>Type the path to a program above and press <b>Analyze</b> (or Enter).
         You will see what the file is made of &mdash; then each view below answers one question about it.</p>
    </div>
    <div id="summary" class="hidden"></div>
    <div id="codeview" class="hidden"><pre id="codepre"></pre></div>
    <div class="table-wrap hidden">
      <table id="tbl">
        <thead><tr></tr></thead>
        <tbody></tbody>
      </table>
    </div>
    <details class="raw">
      <summary>Raw JSON (for scripts and agents)</summary>
      <pre id="out">No request yet.</pre>
    </details>
  </section>

  <section class="card">
    <p class="step-tag"><span class="n">2</span> Dig deeper &mdash; one question per view</p>
    <div class="tools">

      <div class="tool">
        <div class="tool-top"><span class="glyph">fn</span><b>Functions</b></div>
        <p class="desc">What code lives here? Lists candidate functions and how confident we are about each.</p>
        <div class="tool-opts single">
          <div>
            <label for="fn-limit">Max rows</label>
            <input id="fn-limit" type="number" min="1" max="200000" step="1" value="100">
          </div>
        </div>
        <button type="button" data-action="functions">Show functions</button>
      </div>

      <div class="tool">
        <div class="tool-top"><span class="glyph">tx</span><b>Text inside</b></div>
        <p class="desc">Readable strings hidden in the file &mdash; names, messages, URLs, paths.</p>
        <div class="tool-opts">
          <div>
            <label for="st-min">Shortest string</label>
            <input id="st-min" type="number" min="1" max="200000" step="1" value="4">
          </div>
          <div>
            <label for="st-limit">Max rows</label>
            <input id="st-limit" type="number" min="1" max="200000" step="1" value="100">
          </div>
        </div>
        <button type="button" data-action="strings">Show strings</button>
      </div>

      <div class="tool">
        <div class="tool-top"><span class="glyph">xr</span><b>Who calls whom</b></div>
        <p class="desc">Cross-references: every direct call, jump and branch between addresses.</p>
        <div class="tool-opts single">
          <div>
            <label for="xr-limit">Max rows</label>
            <input id="xr-limit" type="number" min="1" max="200000" step="1" value="100">
          </div>
        </div>
        <button type="button" data-action="xrefs">Show xrefs</button>
      </div>

      <div class="tool">
        <div class="tool-top"><span class="glyph">cf</span><b>Code flow</b></div>
        <p class="desc">A control-flow map of one function &mdash; the blocks it runs and where it branches.</p>
        <div class="tool-opts">
          <div class="full mono">
            <label for="cfg-address">Start address</label>
            <input id="cfg-address" type="text" spellcheck="false" autocomplete="off" value="0x401000">
          </div>
          <div class="full">
            <label for="cfg-traversal" title="linear walks a whole region; recursive follows only reachable code">Style</label>
            <div class="selwrap">
              <select id="cfg-traversal">
                <option value="linear">linear &mdash; whole region</option>
                <option value="recursive">recursive &mdash; follow the flow</option>
              </select>
            </div>
          </div>
        </div>
        <button type="button" data-action="cfg">Show code flow</button>
      </div>

      <div class="tool">
        <div class="tool-top"><span class="glyph">st</span><b>Data layouts</b></div>
        <p class="desc">Guesses the struct/layout of data at an address, from how the code reads and writes it.</p>
        <div class="tool-opts">
          <div class="full mono">
            <label for="su-address">Address</label>
            <input id="su-address" type="text" spellcheck="false" autocomplete="off" value="0x401000">
          </div>
          <div>
            <label for="su-max">Max fields</label>
            <input id="su-max" type="number" min="1" max="512" step="1" value="64">
          </div>
          <div>
            <label for="su-stack">Stack vars</label>
            <div class="selwrap">
              <select id="su-stack">
                <option value="0">exclude</option>
                <option value="1">include</option>
              </select>
            </div>
          </div>
        </div>
        <button type="button" data-action="struct">Show layout</button>
      </div>

      <div class="tool">
        <div class="tool-top"><span class="glyph">dc</span><b>Read as C</b></div>
        <p class="desc">Turns the function at an address back into readable C-like pseudocode &mdash; a heuristic sketch, not the original source.</p>
        <div class="tool-opts">
          <div class="full mono">
            <label for="dc-address">Function address</label>
            <input id="dc-address" type="text" spellcheck="false" autocomplete="off" value="0x401000">
          </div>
          <div class="full">
            <label for="backend" title="auto picks the best engine installed; built-in always works">Engine</label>
            <div class="selwrap">
              <select id="backend">
                <option value="auto">auto</option>
                <option value="native">built-in</option>
                <option value="angr">angr</option>
                <option value="ghidra">ghidra</option>
              </select>
            </div>
          </div>
        </div>
        <button type="button" data-action="decompile">Decompile</button>
      </div>

      <div class="tool">
        <div class="tool-top"><span class="glyph">cg</span><b>Call map</b></div>
        <p class="desc">Which functions call which &mdash; the program's overall structure at a glance.</p>
        <div class="tool-opts">
          <div>
            <label for="cg-limit">Max functions</label>
            <input id="cg-limit" type="number" min="1" max="200000" step="1" value="100">
          </div>
          <div>
            <label for="cg-edges">Max edges</label>
            <input id="cg-edges" type="number" min="1" max="200000" step="1" value="5000">
          </div>
        </div>
        <button type="button" data-action="callgraph">Show call map</button>
      </div>

      <div class="tool">
        <div class="tool-top"><span class="glyph">ex</span><b>Emulate</b></div>
        <p class="desc">Runs the function at an address on a sandboxed virtual CPU &mdash; nothing is executed on your machine &mdash; and reports where it stopped, its registers and its return value.</p>
        <div class="tool-opts">
          <div class="full mono">
            <label for="emu-address">Function address</label>
            <input id="emu-address" type="text" spellcheck="false" autocomplete="off" value="0x401000">
          </div>
          <div class="full">
            <label for="emu-max" title="instruction budget for one run">Max instructions</label>
            <input id="emu-max" type="number" min="1" max="100000" step="1" value="2000">
          </div>
        </div>
        <button type="button" id="emu-run" data-action="emulate">Emulate function</button>
      </div>

      <div class="tool">
        <div class="tool-top"><span class="glyph">pa</span><b>Paths</b></div>
        <p class="desc">Explores the branch decisions of one function and lists every path it can take, with the register state each path ends in.</p>
        <div class="tool-opts">
          <div class="full mono">
            <label for="sym-address">Function address</label>
            <input id="sym-address" type="text" spellcheck="false" autocomplete="off" value="0x401000">
          </div>
          <div>
            <label for="sym-max-paths" title="how many paths the explorer may report">Max paths</label>
            <input id="sym-max-paths" type="number" min="1" max="4096" step="1" value="64">
          </div>
          <div>
            <label for="sym-max-steps" title="instruction budget for the whole exploration">Max steps</label>
            <input id="sym-max-steps" type="number" min="1" max="200000" step="1" value="2000">
          </div>
        </div>
        <button type="button" id="sym-run" data-action="symbolic">Explore paths</button>
      </div>

      <div class="tool">
        <div class="tool-top"><span class="glyph">br</span><b>Tool bridges</b></div>
        <p class="desc">Which external tools (binwalk, tshark, objdump and friends) are installed and usable on this machine right now.</p>
        <button type="button" data-action="bridges">Check bridges</button>
      </div>

      <div class="tool">
        <div class="tool-top"><span class="glyph">uk</span><b>Unknowns</b></div>
        <p class="desc">The open questions a run recorded in its unknowns ledger &mdash; what is still unexplained.</p>
        <div class="tool-opts">
          <div class="full mono">
            <label for="uk-ledger">Ledger JSON</label>
            <input id="uk-ledger" type="text" spellcheck="false" autocomplete="off" placeholder="absolute path to an unknowns ledger file">
          </div>
          <div>
            <label for="uk-limit">Max rows</label>
            <input id="uk-limit" type="number" min="0" max="4096" step="1" value="200">
          </div>
        </div>
        <button type="button" data-action="unknowns">List unknowns</button>
      </div>

      <div class="tool">
        <div class="tool-top"><span class="glyph">ob</span><b>Obligations</b></div>
        <p class="desc">The obligations a ledger still demands &mdash; what must be parsed, computed or verified before a claim counts.</p>
        <div class="tool-opts">
          <div class="full mono">
            <label for="ob-ledger">Ledger JSON</label>
            <input id="ob-ledger" type="text" spellcheck="false" autocomplete="off" placeholder="absolute path to an obligations ledger file">
          </div>
        </div>
        <button type="button" data-action="obligations">List obligations</button>
      </div>

      <div class="tool">
        <div class="tool-top"><span class="glyph">cm</span><b>Compare reports</b></div>
        <p class="desc">Diffs two JSON artifacts &mdash; function inventories, string sets or evidence bundles. Uses the Baseline and Candidate paths from the Advanced box below.</p>
        <div class="tool-opts single">
          <div>
            <label for="cmp-what">What to compare</label>
            <div class="selwrap">
              <select id="cmp-what">
                <option value="functions">functions</option>
                <option value="strings">strings</option>
                <option value="bundles">bundles</option>
              </select>
            </div>
          </div>
        </div>
        <button type="button" data-action="compare">Compare reports</button>
      </div>

      <div class="tool">
        <div class="tool-top"><span class="glyph">nv</span><b>Session nav</b></div>
        <p class="desc">The bookmarks, comments and reading cursor one session carries in its navigation database.</p>
        <div class="tool-opts">
          <div class="full mono">
            <label for="nv-db">Database</label>
            <input id="nv-db" type="text" spellcheck="false" autocomplete="off" placeholder="absolute path to a sessions database">
          </div>
          <div class="full mono">
            <label for="nv-session">Session id</label>
            <input id="nv-session" type="text" spellcheck="false" autocomplete="off" placeholder="e.g. the id a saved session printed">
          </div>
        </div>
        <button type="button" data-action="nav">Show navigation</button>
      </div>

      <div class="tool">
        <div class="tool-top"><span class="glyph">md</span><b>Metadata</b></div>
        <p class="desc">Auto-detects what a file or folder is &mdash; .pyc, APK signing, Go build info, Electron fuses and more. Any path, not only the one above.</p>
        <div class="tool-opts single">
          <div class="full mono">
            <label for="md-path">Target path</label>
            <input id="md-path" type="text" spellcheck="false" autocomplete="off" placeholder="absolute path to any file or folder">
          </div>
        </div>
        <button type="button" data-action="metadata">Detect metadata</button>
      </div>

    </div>
  </section>

  <details class="diffbox">
    <summary>Advanced &mdash; compare two versions of the same program</summary>
    <div class="diffbox-body">
      <p class="kv-note" style="margin:0 0 12px">
        Give a baseline and a candidate build; CODEVANTA pairs up functions and shows
        what changed, was added, or disappeared.
      </p>
      <div class="diffgrid">
        <div class="mono">
          <label for="left">Baseline (old)</label>
          <input id="left" type="text" spellcheck="false" autocomplete="off" placeholder="absolute path">
        </div>
        <div class="mono">
          <label for="right">Candidate (new)</label>
          <input id="right" type="text" spellcheck="false" autocomplete="off" placeholder="absolute path">
        </div>
      </div>
      <div class="diffgrid" style="grid-template-columns: 1fr 1fr; max-width:520px">
        <div>
          <label for="semantic">Matching</label>
          <div class="selwrap">
            <select id="semantic">
              <option value="0">structural</option>
              <option value="1">semantic (fuzzy)</option>
            </select>
          </div>
        </div>
        <div>
          <label for="threshold" title="0 pairs everything, 1 demands identical shapes">Strictness</label>
          <input id="threshold" type="number" min="0" max="1" step="0.05" value="0.5">
        </div>
      </div>
      <div style="max-width:220px; margin-top:14px">
        <button type="button" data-action="diff" class="primary" style="width:100%">Compare</button>
      </div>
    </div>
  </details>

  <section class="card" id="sessions">
    <p class="step-tag"><span class="n">3</span> Sessions &mdash; keep what you found</p>
    <p class="hero-hint" style="margin-top:0">
      Saving stores the file above as a session record, so the list is still here after a
      reload, a restart or in another tab. Records live in the local session database and
      the file itself is never modified.
    </p>
    <div class="hero-row">
      <div class="grow mono">
        <label for="session-notes">Note for this session (optional)</label>
        <input id="session-notes" type="text" spellcheck="false" autocomplete="off"
               placeholder="e.g. candidate build, crash repro, reviewed by hand">
      </div>
      <div>
        <label style="visibility:hidden">save</label>
        <button type="button" id="session-save" class="primary" data-action="session_save">Save session</button>
      </div>
    </div>
    <div class="hero-row" style="margin-top:14px">
      <div style="max-width:190px">
        <label for="session-limit" title="how many stored sessions the list asks for">Rows to list</label>
        <input id="session-limit" type="number" min="1" max="10000" step="1" value="50">
      </div>
      <div>
        <label style="visibility:hidden">refresh</label>
        <button type="button" id="session-refresh" data-action="session_list">Refresh list</button>
      </div>
    </div>
    <div class="session-wrap hidden" id="session-wrap" style="margin-top:14px">
      <table id="session-tbl">
        <thead><tr></tr></thead>
        <tbody></tbody>
      </table>
    </div>
    <p class="kv-note" id="session-note" style="margin-top:10px">No sessions loaded yet.</p>
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
    decompile: "/api/decompile",
    emulate: "/api/emulate",
    symbolic: "/api/symbolic",
    session_save: "/api/session_save",
    session_list: "/api/session_list",
    bridges: "/bridges",
    unknowns: "/unknowns",
    obligations: "/obligations",
    compare: "/compare",
    nav: "/nav",
    metadata: "/metadata"
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

  function showView(name) {
    var empty = byId("empty");
    var summary = byId("summary");
    var codeview = byId("codeview");
    var tableWrap = document.querySelector(".table-wrap");
    if (empty) {
      empty.className = name === "empty" ? "" : "hidden";
    }
    if (summary) {
      summary.className = name === "summary" ? "" : "hidden";
    }
    if (codeview) {
      codeview.className = name === "code" ? "" : "hidden";
    }
    if (tableWrap) {
      tableWrap.className = name === "table" ? "table-wrap" : "table-wrap hidden";
    }
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
    // The session routes accept a closed set of parameters and answer anything
    // else with 400, so they are built here instead of falling through to the
    // generic "path" line below: the list route takes no path at all.
    if (action === "session_save") {
      addParam(parts, "path", fieldValue("path"));
      addParam(parts, "notes", fieldValue("session-notes"));
      return parts;
    }
    if (action === "session_list") {
      addParam(parts, "limit", fieldValue("session-limit"));
      return parts;
    }
    // The lane routes have their own parameter sets and return before the
    // generic "path" line below, so the main binary input never leaks into
    // a request that does not use it.
    if (action === "bridges") {
      return parts;
    }
    if (action === "unknowns") {
      addParam(parts, "ledger", fieldValue("uk-ledger"));
      addParam(parts, "limit", fieldValue("uk-limit"));
      return parts;
    }
    if (action === "obligations") {
      addParam(parts, "ledger", fieldValue("ob-ledger"));
      return parts;
    }
    if (action === "compare") {
      addParam(parts, "left", fieldValue("left"));
      addParam(parts, "right", fieldValue("right"));
      addParam(parts, "what", fieldValue("cmp-what") || "functions");
      return parts;
    }
    if (action === "nav") {
      addParam(parts, "db", fieldValue("nv-db"));
      addParam(parts, "session", fieldValue("nv-session"));
      return parts;
    }
    if (action === "metadata") {
      addParam(parts, "path", fieldValue("md-path"));
      return parts;
    }
    addParam(parts, "path", fieldValue("path"));
    if (action === "info") {
      addParam(parts, "max_functions", fieldValue("fn-limit"));
    } else if (action === "functions") {
      addParam(parts, "limit", fieldValue("fn-limit"));
    } else if (action === "xrefs") {
      addParam(parts, "limit", fieldValue("xr-limit"));
    } else if (action === "strings") {
      addParam(parts, "limit", fieldValue("st-limit"));
      addParam(parts, "min_length", fieldValue("st-min"));
    } else if (action === "cfg") {
      addParam(parts, "address", fieldValue("cfg-address"));
      addParam(parts, "traversal", fieldValue("cfg-traversal") || "linear");
    } else if (action === "struct") {
      addParam(parts, "address", fieldValue("su-address"));
      addParam(parts, "include_stack", fieldValue("su-stack") || "0");
      addParam(parts, "max_fields", fieldValue("su-max"));
    } else if (action === "callgraph") {
      addParam(parts, "limit_functions", fieldValue("cg-limit"));
      addParam(parts, "limit_edges", fieldValue("cg-edges"));
    } else if (action === "decompile") {
      addParam(parts, "address", fieldValue("dc-address"));
      addParam(parts, "backend", fieldValue("backend") || "auto");
    } else if (action === "emulate") {
      addParam(parts, "address", fieldValue("emu-address"));
      addParam(parts, "max_instructions", fieldValue("emu-max"));
    } else if (action === "symbolic") {
      addParam(parts, "address", fieldValue("sym-address"));
      addParam(parts, "max_paths", fieldValue("sym-max-paths"));
      addParam(parts, "max_steps", fieldValue("sym-max-steps"));
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
      "entries",
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

  // Columns of the Sessions panel, in display order. They are the fields
  // /api/session_list returns, spelled once so the header and the cells can
  // never drift apart.
  var SESSION_COLUMNS = [
    "session_id",
    "created_at",
    "path",
    "format",
    "architecture",
    "notes"
  ];

  function setSessionNote(message, isError) {
    var element = byId("session-note");
    if (!element) {
      return;
    }
    element.textContent = message;
    element.className = isError ? "kv-note error" : "kv-note";
  }

  function sessionRows(data) {
    if (!data || typeof data !== "object" || !isRowList(data.sessions)) {
      return [];
    }
    return data.sessions;
  }

  function renderSessions(data) {
    var table = byId("session-tbl");
    var wrap = byId("session-wrap");
    var rows = sessionRows(data);
    if (!table || !table.tHead || !table.tBodies.length) {
      return rows.length;
    }
    var head = table.tHead.rows[0];
    var body = table.tBodies[0];
    while (head.cells.length > 0) {
      head.deleteCell(-1);
    }
    while (body.firstChild) {
      body.removeChild(body.firstChild);
    }
    SESSION_COLUMNS.forEach(function (name) {
      var cell = document.createElement("th");
      cell.textContent = name;
      head.appendChild(cell);
    });
    rows.slice(0, MAX_TABLE_ROWS).forEach(function (row) {
      var tr = document.createElement("tr");
      SESSION_COLUMNS.forEach(function (name) {
        var td = document.createElement("td");
        // textContent only: a path or a note is attacker-controlled text and is
        // never parsed as markup.
        td.textContent = cellText(row && typeof row === "object" ? row[name] : row);
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    if (wrap) {
      wrap.className = rows.length ? "session-wrap" : "session-wrap hidden";
    }
    return rows.length;
  }

  function loadSessions(announce) {
    // Used on page load and after a save: it keeps the panel current without
    // touching the status line or the raw-JSON box the user may be reading.
    // ``announce`` says whether the panel note may be rewritten -- the startup
    // call wants the restored count, while the refresh that follows a save must
    // leave the "saved <id>" confirmation in place.
    var parts = [];
    addParam(parts, "limit", fieldValue("session-limit"));
    var url = ENDPOINTS.session_list + (parts.length ? "?" + parts.join("&") : "");
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
        if (!result.ok) {
          if (announce) {
            var detail = result.data && result.data.error ? result.data.error : "request failed";
            setSessionNote("HTTP " + result.status + " " + detail, true);
          }
          return;
        }
        var count = renderSessions(result.data);
        if (announce) {
          if (count > 0) {
            setSessionNote(count + " saved session(s) restored from the session database", false);
          } else {
            setSessionNote("No sessions stored yet \u2014 pick a file and press Save session.", false);
          }
        }
      })
      .catch(function (error) {
        if (announce) {
          setSessionNote("session list failed: " + String(error), true);
        }
      });
  }

  function humanSize(bytes) {
    var value = Number(bytes);
    if (!isFinite(value) || value < 0) {
      return String(bytes);
    }
    if (value < 1024) {
      return value + " B";
    }
    if (value < 1024 * 1024) {
      return (value / 1024).toFixed(1) + " KB";
    }
    return (value / (1024 * 1024)).toFixed(1) + " MB";
  }

  function chipRow(container, key, value, accent) {
    var chip = document.createElement("span");
    chip.className = accent ? "chip acc" : "chip";
    var k = document.createElement("span");
    k.className = "k";
    k.textContent = key;
    var v = document.createElement("span");
    v.className = "v";
    v.textContent = value;
    chip.appendChild(k);
    chip.appendChild(v);
    container.appendChild(chip);
  }

  function kvRow(container, key, value) {
    var row = document.createElement("div");
    row.className = "kv-row";
    var k = document.createElement("div");
    k.className = "k";
    k.textContent = key;
    var v = document.createElement("div");
    v.className = "v";
    v.textContent = value;
    row.appendChild(k);
    row.appendChild(v);
    container.appendChild(row);
  }

  function renderSummary(payload) {
    var box = byId("summary");
    if (!box) {
      return;
    }
    while (box.firstChild) {
      box.removeChild(box.firstChild);
    }
    var binary = payload && payload.binary && typeof payload.binary === "object" ? payload.binary : {};

    var chips = document.createElement("div");
    chips.className = "chips";
    var archBits = [binary.format, binary.architecture, binary.bitness ? binary.bitness + "-bit" : ""]
      .filter(Boolean).join(" · ");
    chipRow(chips, "file", archBits || "unknown", true);
    if (binary.sections) {
      chipRow(chips, "sections", String(binary.sections.length));
    }
    if (binary.imports) {
      chipRow(chips, "imports", String(binary.imports.length));
    }
    if (binary.exports) {
      chipRow(chips, "exports", String(binary.exports.length));
    }
    if (binary.symbols) {
      chipRow(chips, "symbols", String(binary.symbols.length));
    }
    if (payload.function_count !== undefined) {
      chipRow(chips, "functions", String(payload.function_count));
    }
    if (payload.string_count !== undefined) {
      chipRow(chips, "strings", String(payload.string_count));
    }
    if (binary.is_stripped !== undefined) {
      chipRow(chips, "symbols?", binary.is_stripped ? "stripped" : "present");
    }
    box.appendChild(chips);

    var kv = document.createElement("div");
    kv.className = "kv";
    if (binary.path) {
      kvRow(kv, "Path", binary.path);
    }
    if (binary.entry_point) {
      kvRow(kv, "Program start (entry point)", binary.entry_point);
    }
    if (binary.image_base) {
      kvRow(kv, "Image base", binary.image_base);
    }
    if (binary.file_size !== undefined) {
      kvRow(kv, "File size", humanSize(binary.file_size));
    }
    if (binary.sha256) {
      kvRow(kv, "SHA-256", binary.sha256);
    }
    if (binary.warnings && binary.warnings.length) {
      kvRow(kv, "Notes", binary.warnings.join("  |  "));
    }
    box.appendChild(kv);

    var note = document.createElement("p");
    note.className = "kv-note";
    var lead = document.createElement("b");
    lead.textContent = "Next: ";
    note.appendChild(lead);
    note.appendChild(document.createTextNode(
      "pick any view below to dig deeper \u2014 every result keeps its evidence and confidence level."
    ));
    box.appendChild(note);
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
          if (action === "decompile" && result.data && typeof result.data.text === "string") {
            var codeBox = byId("codepre");
            if (codeBox) {
              codeBox.textContent = result.data.text;
            }
            showView("code");
            var engineName = result.data.backend ? String(result.data.backend) : "?";
            var warnCount = result.data.warnings && result.data.warnings.length
              ? " · " + result.data.warnings.length + " warning(s)"
              : "";
            setStatus("HTTP " + result.status + " · engine " + engineName + warnCount, false);
          } else if (action === "session_list") {
            var listed = renderSessions(result.data);
            setSessionNote(
              "HTTP " + result.status + " \u00b7 " + listed + " session(s) in the list",
              false
            );
            setStatus("HTTP " + result.status + " \u00b7 " + listed + " session(s)", false);
          } else if (action === "session_save") {
            var savedId = result.data && result.data.session_id
              ? String(result.data.session_id)
              : "?";
            var savedAt = result.data && result.data.created_at
              ? String(result.data.created_at)
              : "?";
            setSessionNote("saved " + savedId + " at " + savedAt, false);
            setStatus("HTTP " + result.status + " \u00b7 session saved", false);
            // Refresh the table but keep the "saved <id>" note that was just
            // written, which is the confirmation the user asked for.
            loadSessions(false);
          } else if (action === "info") {
            renderSummary(result.data);
            showView("summary");
            setStatus("HTTP " + result.status + " · overview", false);
          } else {
            var rows = pickRows(result.data);
            renderTable(rows);
            showView(rows.length ? "table" : "empty");
            var shown = Math.min(rows.length, MAX_TABLE_ROWS);
            var summary = "HTTP " + result.status + (rows.length ? " · " + shown + (rows.length > MAX_TABLE_ROWS ? " of " + rows.length : "") + " rows" : " · no rows");
            setStatus(summary, false);
          }
          var resultCard = document.querySelector(".card.result");
          // A session request reports in its own panel, so the page must not
          // scroll the main result card into view for it.
          if (resultCard && resultCard.scrollIntoView && action.indexOf("session") !== 0) {
            resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
          }
        } else {
          var detail = result.data && result.data.error ? result.data.error : "request failed";
          setStatus("HTTP " + result.status + " " + detail, true);
          renderTable([]);
          showView("empty");
          if (action.indexOf("session") === 0) {
            setSessionNote("HTTP " + result.status + " " + detail, true);
          }
        }
      })
      .catch(function (error) {
        showPayload({ error: String(error) });
        setStatus("request failed", true);
        renderTable([]);
        showView("empty");
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

  // Reload the stored history as soon as the page opens: this is what makes a
  // session survive a reload. It leaves the "idle" status line and the empty
  // raw-JSON box alone and reports the restored count in the panel note.
  loadSessions(true);
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
