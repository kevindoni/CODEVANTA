# Network capture around a target command

Two MCP tools, `codevanta_net_interfaces` and `codevanta_net_capture`,
put a **tshark** recording around a command you run locally:
`interfaces` lists what can be captured on; `capture` starts a
background tshark, runs your command as an owned bounded subprocess,
auto-stops the recording, then summarises the finished pcap offline
through the tshark bridge read path.

Unlike the [session lanes](sessions.md) these tools are **stateless**:
each capture returns its full record once, and the pcap file itself is
the artifact.

## What it reports

* `codevanta_net_interfaces()` — what `tshark -D` can capture on, one
  `{number, device, description}` row per interface, capped at 32.
  When tshark is not on PATH the tool returns an honest **unavailable
  object** (`available: false` with the install hint) instead of an
  error.
* `codevanta_net_capture(command, arguments, capture_seconds,
  interface, output_directory)` — the composed record: the pcap's
  `path`, `size` and `sha256`, the target's argv, exit code and output
  streams, the offline pcap summary (frame count and first-packet
  fields), and evidence (`source: net.capture`, `method:
  tshark-around-run`, `high` confidence).

Every degraded step is a **stage-named warning**: `tshark-start`,
`tshark-join`, `pcap-missing`, `summary`.

## Security and privilege notes

* **The tool EXECUTES the command you pass** — locally, on this
  machine, as an owned child process — **and RECORDS this machine's
  network packets**. This is dynamic analysis; pass only commands you
  intend to run. Both facts are stated in the tool's own description.
* Live capture is **privileged**: it needs administrator rights and
  Npcap/WinPcap on Windows. Without them tshark may start yet record
  nothing — the warnings say so; a listed interface does not guarantee
  packets can be recorded.
* When tshark is missing entirely, **nothing runs at all**: the
  unavailable result comes back (`available: false`, confidence `low`,
  detail "tshark is not on PATH; the target was NOT run") and the
  target command is not executed.

## Usage

```json
{"command": "curl", "arguments": ["-s", "http://example.invalid"], "capture_seconds": 10,
 "interface": "\\Device\\NpcapLoopbackAdapter_", "output_directory": "C:\\sandbox"}
```

Python surface:

```python
from codevanta.analysis.net_capture import list_interfaces, capture_around

interfaces = list_interfaces()          # honest unavailable dict without tshark
result = capture_around("curl", ["-s", "http://example.invalid"], 10, interfaces, "out")
print(result.to_dict()["pcap"]["sha256"])
```

Caller mistakes (out-of-range `capture_seconds`, too many arguments,
missing output directory) are typed errors; a missing tshark is the
honest unavailable result and runs nothing.

## Bounds and confidence

| Bound | Default | Effect |
|-------|---------|--------|
| Capture window | 1…60 s (`capture_seconds`) | out-of-range is a typed error |
| Target arguments | 32 | more are a typed error |
| tshark join | bounded | a hung tshark cannot block the tool; `tshark-join` warning |
| Interface list | 32 entries | capped, flag set when hit |

| Finding | Confidence | Why |
|---------|------------|-----|
| The composed capture record | `high` | the pcap's own sha256 and the subprocess result are read back after the fact |
| The offline pcap summary | `high` | produced by the same tshark bridge read path used by the replay lane |
| The unavailable result (no tshark) | `low` | a probe result; it states that nothing was captured and nothing ran |

## Limitations

* No session registry — a capture cannot be "restarted" or polled;
  re-invoke the tool for a fresh run.
* Without administrator rights and Npcap/WinPcap the recording may be
  empty while the target still runs; read the stage-named warnings
  before trusting an empty summary.
* The pcap summary is first-packet-shaped (frame count and first
  fields), not a protocol decode; deep pcap analysis belongs to
  Wireshark or the replay lane's HAR fixtures.
