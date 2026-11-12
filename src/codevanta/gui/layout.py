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
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 24px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  background: #0f1115;
  color: #d7dce5;
}
header { margin: 0 0 20px; }
h1 {
  margin: 0 0 6px;
  font-size: 20px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #7fe3c0;
}
h2 {
  margin: 0 0 12px;
  font-size: 13px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: #8b97a8;
}
.hint { margin: 0; font-size: 12px; color: #6b7686; }
.grid {
  display: grid;
  gap: 16px;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
}
.card {
  border: 1px solid #232a35;
  border-radius: 8px;
  background: #151922;
  padding: 16px;
}
label {
  display: block;
  margin: 0 0 4px;
  font-size: 11px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: #8b97a8;
}
input, select {
  width: 100%;
  margin: 0 0 12px;
  padding: 7px 9px;
  border: 1px solid #2c3542;
  border-radius: 5px;
  background: #0f131a;
  color: #e6ebf3;
  font: inherit;
  font-size: 13px;
}
input:focus, select:focus { outline: 1px solid #4fd1a5; border-color: #4fd1a5; }
.row {
  display: grid;
  gap: 12px;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
}
.buttons { display: flex; flex-wrap: wrap; gap: 8px; }
button {
  padding: 7px 12px;
  border: 1px solid #2f6f5c;
  border-radius: 5px;
  background: #16302a;
  color: #9df0d2;
  font: inherit;
  font-size: 12px;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  cursor: pointer;
}
button:hover { background: #1d433a; }
button[data-action="diff"] {
  border-color: #6f5c2f;
  background: #302a16;
  color: #f0df9d;
}
.status {
  font-size: 11px;
  letter-spacing: 0;
  text-transform: none;
  color: #6b7686;
}
.status.error { color: #ff9a9a; }
pre#out {
  margin: 0 0 12px;
  padding: 12px;
  max-height: 340px;
  overflow: auto;
  border: 1px solid #232a35;
  border-radius: 6px;
  background: #0b0e14;
  font-size: 12px;
  line-height: 1.45;
  white-space: pre-wrap;
  word-break: break-word;
}
table#tbl { width: 100%; border-collapse: collapse; font-size: 12px; }
table#tbl th, table#tbl td {
  padding: 5px 8px;
  border-bottom: 1px solid #232a35;
  text-align: left;
  vertical-align: top;
}
table#tbl th {
  color: #8b97a8;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}
.wide { grid-column: 1 / -1; }
"""

_BODY = """
<header>
  <h1>__TITLE__</h1>
  <p class="hint">
    Local dashboard over the CODEVANTA analysis engines. Read-only: files are parsed,
    never executed or modified, and nothing leaves this machine.
  </p>
</header>
<main class="grid">
  <section class="card">
    <h2>Single binary</h2>
    <label for="path">Path</label>
    <input id="path" type="text" spellcheck="false" autocomplete="off"
           placeholder="absolute path to a PE, ELF or Mach-O file">
    <div class="row">
      <div>
        <label for="address">Address (hex or decimal)</label>
        <input id="address" type="text" spellcheck="false" autocomplete="off" value="0x401000">
      </div>
      <div>
        <label for="limit">Limit</label>
        <input id="limit" type="number" min="0" max="200000" step="1" value="100">
      </div>
    </div>
    <div class="row">
      <div>
        <label for="min_length">Strings: min length</label>
        <input id="min_length" type="number" min="1" max="200000" step="1" value="4">
      </div>
      <div>
        <label for="max_fields">Struct: max fields</label>
        <input id="max_fields" type="number" min="1" max="512" step="1" value="64">
      </div>
      <div>
        <label for="limit_edges">Callgraph: max edges</label>
        <input id="limit_edges" type="number" min="1" max="200000" step="1" value="5000">
      </div>
    </div>
    <div class="row">
      <div>
        <label for="traversal">CFG traversal</label>
        <select id="traversal">
          <option value="linear">linear</option>
          <option value="recursive">recursive</option>
        </select>
      </div>
      <div>
        <label for="include_stack">Struct: include stack</label>
        <select id="include_stack">
          <option value="0">no</option>
          <option value="1">yes</option>
        </select>
      </div>
    </div>
    <div class="buttons">
      <button type="button" data-action="info">Info</button>
      <button type="button" data-action="functions">Functions</button>
      <button type="button" data-action="strings">Strings</button>
      <button type="button" data-action="xrefs">Xrefs</button>
      <button type="button" data-action="cfg">CFG</button>
      <button type="button" data-action="struct">Struct</button>
      <button type="button" data-action="callgraph">Callgraph</button>
    </div>
  </section>

  <section class="card">
    <h2>Diff two binaries</h2>
    <label for="left">Left (baseline)</label>
    <input id="left" type="text" spellcheck="false" autocomplete="off" placeholder="absolute path">
    <label for="right">Right (candidate)</label>
    <input id="right" type="text" spellcheck="false" autocomplete="off" placeholder="absolute path">
    <div class="row">
      <div>
        <label for="semantic">Mode</label>
        <select id="semantic">
          <option value="0">structural</option>
          <option value="1">semantic</option>
        </select>
      </div>
      <div>
        <label for="threshold">Semantic threshold</label>
        <input id="threshold" type="number" min="0" max="1" step="0.05" value="0.5">
      </div>
    </div>
    <div class="buttons">
      <button type="button" data-action="diff">Diff</button>
    </div>
  </section>

  <section class="card wide">
    <h2>Result <span class="status" id="status">idle</span></h2>
    <pre id="out">No request yet. Pick a binary and press a button.</pre>
    <table id="tbl">
      <thead><tr></tr></thead>
      <tbody></tbody>
    </table>
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
    diff: "/api/diff"
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
          setStatus("HTTP " + result.status, false);
          renderTable(pickRows(result.data));
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

