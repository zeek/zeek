---
name: scapy-pcap
description: >-
  Create or rewrite a Zeek btest PCAP generator script (a
  testing/btest/Traces/**/*.pcap.py that produces a packet trace). Use when
  asked to write, rewrite, or modernize a trace generator, especially to move a
  hand-rolled struct/checksum builder onto Scapy's high-level API, make packet
  timestamps deterministic, or optionally emit a reproducible gzip-compressed
  pcap when the trace is highly compressible.
---

# Zeek Scapy PCAP generators

Convention for the Python scripts under `testing/btest/Traces/` that generate
packet traces for btests. Follow these rules when creating a new generator or
rewriting an existing one.

## Placement and naming

- The generator is always named `<name>.pcap.py` and lives next to the trace it
  produces: `testing/btest/Traces/<protocol>/<name>.pcap.py`, and running it must
  reproducibly write the trace beside itself — `<name>.pcap`, or `<name>.pcap.gz`
  when compressed (see "Output" below).
- `<name>` is dash-separated and names the thing under test, e.g.
  `non-numeric-content-length`, `mime-folded-header-state-memory-exhaustion`.

## Use Scapy's high-level API

- Build packets with `Ether()/IP()/TCP()/Raw()` and write with `wrpcap()`.
  Do NOT hand-roll IP/TCP headers, Internet checksums, or the pcap file header
  with `struct` — Scapy computes checksums and lengths.
- Factor a single `pkt(...)` helper that takes direction (orig vs. resp),
  sequence/ack, TCP flags (as a string like `"S"`, `"SA"`, `"PA"`, `"A"`), and
  an optional payload. Only attach `Raw` when there is a payload.
- Bracket the flow with a real TCP lifecycle: open with the SYN / SYN-ACK / ACK
  handshake and close with a FIN/ACK teardown — client `"FA"`, server `"FA"`,
  client `"A"` — so the trace is a complete, well-formed connection rather than
  one that just stops mid-flow or trails off on a bare ACK. Besides being
  well-formed, a proper teardown matters for `tcpreplay`-style scenarios: a
  connection that is explicitly closed lets the replayed flow terminate and its
  state be released, instead of lingering until a timeout. A FIN consumes one
  sequence number, so bump the sender's seq by one after each FIN (and the
  peer's ack matches):

  ```python
  packets.append(pkt(True, client_seq, server_seq, "FA"))
  client_seq += 1
  packets.append(pkt(False, server_seq, client_seq, "FA"))
  server_seq += 1
  packets.append(pkt(True, client_seq, server_seq, "A"))
  ```

  If the client has unacknowledged server data when it closes (e.g. after
  receiving a large burst that it has not yet ACKed), send a plain `"A"` first
  to clear the backlog; the teardown then becomes 4 packets:
  `"A"` / `"FA"` / `"FA"` / `"A"`.

  Verify the teardown with `tshark`: the last three (or four) packets should be
  `[FIN, ACK]` / `[FIN, ACK]` / `[ACK]` (optionally preceded by a plain `[ACK]`)
  with no `tcp.analysis.flags`.
  The exception is when the incomplete flow *is* the thing under test — a
  half-duplex connection, pre-banner data, a mid-flow reset, a never-closed
  connection. Then build exactly the (possibly partial) flow the test needs and
  do not paper over it with a synthetic handshake or teardown.
- The `pkt(...)` direction helper, the SYN handshake, and the FIN/ACK teardown
  above are TCP-specific. For a connectionless (UDP) or single-packet trace
  they do not apply — do not synthesize a handshake or teardown, and do not add
  a direction/seq/ack helper the flow does not need. Build the packet(s)
  directly (`Ether()/IP()/UDP()/...`, or an L7 Scapy layer) and keep it
  minimal. Everything else in this skill still applies: build with Scapy's
  high-level API, derive the output path from `__file__`, and assign
  deterministic timestamps.
- Prefer a protocol-specific Scapy layer over hand-rolling the application
  payload with `struct`, too. Scapy ships dissectors for many L7 protocols under
  `scapy.layers.<proto>` (e.g. `SMB2_Header` and `NBTSession` in
  `scapy.layers.smb2`/`netbios`, plus DNS, TLS, Kerberos, LDAP, …), and more
  under `scapy.contrib` (e.g. IGMP, GENEVE) — both are fair game. Check for
  one before reaching for `struct`: `from scapy.layers.smb2 import SMB2_Header`;
  `bytes(NBTSession() / SMB2_Header(Command=..., MID=..., TID=...))`. If a field
  is missing from the layer, set it explicitly rather than abandoning the layer.
  Only fall back to a small fixed `Raw` blob for a body Scapy has no class for,
  and spell it out with a comment naming each field (a 4-byte command body is
  fine; a full header is not — use the layer).

## Output: plain by default, optional gzip

- Default to a plain, uncompressed `<name>.pcap`. Hardcode the path from
  `__file__` and don't add a positional output argument:
  `wrpcap(str(Path(__file__).with_suffix("")), packets)`. Since the script is
  `<name>.pcap.py`, `with_suffix("")` strips the `.py` and yields `<name>.pcap`.
  A bare string default (e.g. `default="<name>.pcap"`) silently writes to
  whatever the working directory is at invocation time — not next to the script.
  `Path(__file__)` is always correct regardless of CWD.
- Keep traces small — `btest.rst` asks for a few kilobytes, with 50 KB or more
  being an exception. Include only the packets the behavior under test needs.
- gzip is OPTIONAL — only worth it for the large, highly compressible traces
  that are the exception above (repetitive payloads, e.g. resource-exhaustion
  reproducers that shrink by 50x+). For a normal small trace, leave it
  uncompressed; a plain pcap is nicer to inspect and diff.
- When you do compress, write through `gzip.GzipFile(path, "wb", mtime=0)` and
  pass that handle to `wrpcap(f, packets)`. `mtime=0` is what makes the bytes
  reproducible; do NOT use `wrpcap(..., gz=1)`, which embeds a build-time mtime.
  The output is then `<name>.pcap.gz`:
  `gzip.GzipFile(Path(__file__).with_suffix(".gz"), "wb", mtime=0)`.
  `with_suffix(".gz")` replaces only the `.py` and yields `<name>.pcap.gz`.
  (Do NOT use `with_suffix(".pcap.gz")` — that would produce `<name>.pcap.pcap.gz`.)
- pcapng is fine when the trace needs it — e.g. per-packet capture length that
  differs from wire length (a truncated packet), which the pcap format cannot
  represent. Name the script `<name>.pcapng.py`, write with `wrpcapng(...)`, and
  the output is `<name>.pcapng`. `with_suffix("")` on `<name>.pcapng.py` still
  strips only `.py` and yields `<name>.pcapng`.
- Streaming with `PcapWriter` / `PcapNgWriter` instead of collecting a list and
  calling `wrpcap()` is also fine. Set a deterministic `.time` on each packet as
  you write it (the determinism rules below still apply), and derive the path
  from `__file__` the same way.

## Deterministic timestamps

- Never read the clock or environment (`time.time()`, dates, hostnames, randomness).
  Running the script a year later must produce identical bytes. Concretely:
  - Do NOT call `time.time()`, `datetime.now()`, `random.*`, `os.urandom()`, or
    `socket.gethostname()` — a field that needs a "random" value (a nonce, an
    ephemeral MAC/IP/port, a TLS `Random`) gets a hardcoded literal instead.
  - Do NOT leave timestamps unset. A packet with no `.time` is written with the
    wall-clock time at generation, so the bytes change on every run. Assign
    `.time` on every packet (see below), including single-packet traces.
- Assign timestamps in a single pass right before writing, from a fixed base:

  ```python
  for index, p in enumerate(packets):
      p.time = BASE_TIME + index * 0.001
  ```

  with a constant like `BASE_TIME = 1_700_000_000.0`. Do not thread a running
  timestamp through the packet builders.

## Keep it minimal

- Drop options that are not generally useful (e.g. an "in-order" or
  "answered-control" companion mode) unless the test actually needs them. Prefer
  a single target generator.
- Running the script with NO arguments must reproduce the exact trace that is
  checked in (the btest baseline was captured against that trace). So avoid a
  scale knob like `--messages`/`--requests` whose default silently diverges from
  the committed trace: if the committed trace has N messages, a bare
  `python3 <name>.pcap.py` must regenerate those N messages byte-for-byte.
  Prefer a hardcoded module-level constant (e.g. `MESSAGE_COUNT = 1000`) over an
  argparse flag. Only add a CLI knob when regenerating at a different scale is
  genuinely useful, and even then keep its default equal to the committed size.

## Attribution

- Keep the `#!/usr/bin/env python3` shebang if the original had one.
- In the module docstring, keep the provenance of the original reproducer and
  append the adapting model's identifier, e.g.:
  "Generated with OpenAI Codex, adapted with <model-id> to use Scapy and gzip
  compress by default." Follow the repo's `AI_POLICY.md`.

## Format and lint the generator

- Run both ruff commands on the finished script — the repo's
  `.pre-commit-config.yaml` runs `ruff-format` and `ruff-check`, and a commit
  fails the hook otherwise. This is easy to forget:

  ```
  ruff format <name>.pcap.py   # reformat in place
  ruff check <name>.pcap.py    # lint
  ```

  Reformatting only touches the Python source (e.g. wrapping long
  `add_argument(...)` calls); it does not change the generated trace bytes, so no
  need to regenerate afterwards. Confirm both are clean with
  `ruff format --check <name>.pcap.py` and `ruff check <name>.pcap.py`.

## Verify before finishing

1. Run the script twice and confirm identical bytes — `sha256sum` must match
   across runs (reproducibility). This applies to a plain `<name>.pcap` just as
   much as a `<name>.pcap.gz`; a differing hash means a timestamp, nonce, or
   other nondeterministic value leaked in (see "Deterministic timestamps").
2. Decompress and sanity-check structure independently of Zeek — the point of a
   reproducer is not to trust Zeek's own parser:
   ```python
   from scapy.all import rdpcap, Raw
   ps = rdpcap("<name>.pcap")
   # assert packet count, TCP flags on the handshake, payload contents,
   # direction counts, first/last timestamps
   ```
   Note that `rdpcap` only re-parses the bytes Scapy itself just wrote, so it
   confirms almost nothing about whether the L7 payload is well-formed — Scapy
   will happily read back a nonsense command code it wrote.
3. Cross-check with `tshark` (a genuinely independent dissector) — treat this as
   required, not optional, for any trace with an application-layer payload. It
   catches malformed payloads Scapy misses. Read a compressed trace over stdin:
   ```
   zcat <name>.pcap.gz | tshark -r -
   ```
   Scan the summary column for `[Malformed Packet]` / `unknown` and check the
   expert info (`-Y "_ws.malformed || _ws.expert.severity==error"` should be
   empty; `-T fields -e <proto>.<field>` to confirm per-message fields). If a
   real dissector flags the trace, pick protocol field values it accepts —
   e.g. a valid command code, not a reserved/unknown one that renders every
   packet malformed. Also make sure the message type you pick actually exercises
   the behavior under test without a side effect that undoes it (e.g. for an SMB2
   tree-id state-growth reproducer, ECHO grows the map but TREE_DISCONNECT has a
   handler that clears it).

   **Exception — intentionally malformed traces:** when the trace is *testing
   Zeek's handling of invalid input* (truncated headers, unknown opcodes,
   out-of-range field values, etc.), tshark dissector errors are expected and
   intentional. In that case, confirm that tshark flags *exactly* the packets
   you intended to be malformed and none of the surrounding framing (handshake,
   teardown, surrounding well-formed messages). Do not "fix" the payload to
   satisfy tshark — the bad input is the point of the test.

See the templates in this skill's `assets/` directory for a minimal starting
point: `assets/template.pcap.py` for a TCP flow (handshake, direction-aware
`pkt()` helper, teardown) and `assets/template-udp.pcap.py` for a
connectionless/single-packet trace.
