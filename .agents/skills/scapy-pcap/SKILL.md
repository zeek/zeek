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

- The generator is named `<name>.pcap.py` and lives next to the trace it
  produces:
  `testing/btest/Traces/<protocol>/<name>.pcap.py`. Running it must
  reproducibly write the trace beside itself — `<name>.pcap`, or `<name>.pcap.gz`
  when compressed (see "Output" below).
- `<name>` is dash-separated and names the thing under test, e.g.
  `non-numeric-content-length`, `mime-folded-header-state-memory-exhaustion`.
- The `.py` is a build-time generator, not part of the test run: you run it once
  and commit the trace it produces (`<name>.pcap` / `.pcap.gz` / `.pcapng`)
  alongside it. btests read the committed trace — they never execute the `.py` —
  so the generator exists to reproducibly regenerate that checked-in trace.

## Use Scapy's high-level API

- Build packets by stacking Scapy layers and write with `wrpcap()` — whatever
  the trace needs: `Ether()/IP()/TCP()` for a TCP flow, `Ether()/IP()/UDP()`
  for a datagram, a protocol-specific L7 layer (see below), or just
  `Ether()/IP()/Raw()` for a hand-specified payload. Do NOT hand-roll IP, TCP,
  or UDP headers, Internet checksums, or the pcap file header with `struct` —
  Scapy computes checksums and lengths.
- The next three bullets (the direction-aware `pkt()` helper, the SYN handshake,
  and the FIN/ACK teardown) are specific to **TCP** flows. For a connectionless
  (UDP) or single-packet trace they do not apply — skip to the UDP note below.
- Factor a single `pkt(...)` helper that takes direction (orig vs. resp),
  sequence/ack, TCP flags (as a string like `"S"`, `"SA"`, `"PA"`, `"A"`), and
  an optional payload. Only attach `Raw` when there is a payload.
- Bracket the flow with a real TCP lifecycle: open with the SYN / SYN-ACK / ACK
  handshake and close with a FIN/ACK teardown — the closing side sends `"FA"`,
  its peer `"FA"`, and the closing side the final `"A"` — so the trace is a
  complete, well-formed connection rather than one that just stops mid-flow or
  trails off on a bare ACK. Either side may close; close from the side that
  does so in the behavior under test (the template closes from the TCP
  originator). Besides being well-formed, a proper teardown matters for
  `tcpreplay`-style scenarios: a connection that is explicitly closed lets the
  replayed flow terminate and its state be released, instead of lingering
  until a timeout. A FIN consumes one sequence number, so bump the sender's seq
  by one after each FIN (and the peer's ack matches) — see the teardown in
  `assets/template-tcp.pcap.py`.

  The closing side's `"FA"` also acknowledges any pending data from its peer.

  The exception is when the incomplete flow *is* the thing under test — a
  half-duplex connection, pre-banner data, a mid-flow reset, a never-closed
  connection. Then build exactly the (possibly partial) flow the test needs and
  do not paper over it with a synthetic handshake or teardown.
- **UDP / single-packet note.** For a connectionless (UDP) or single-packet
  trace, do not synthesize a handshake or teardown, and do not add a
  direction/seq/ack helper the flow does not need. Build the packet(s) directly
  (`Ether()/IP()/UDP()/...`, or an L7 Scapy layer) and keep it minimal.
  Everything else in this skill still applies: build with Scapy's high-level
  API, derive the output path from `__file__`, and assign deterministic
  timestamps.
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
- gzip is optional and only worth it for large, highly compressible traces;
  pcapng only when absolutely necessary. A truncated packet works in
  plain pcap: set `p.wirelen` above the captured length. For either, follow
  `assets/compression-and-pcapng.md` — reproducible gzip output needs
  `mtime=0`, and gzipping pcapng needs a workaround.

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
- Give the module a docstring that says what the trace exercises and records
  the AI assistance per the repo's `AI_POLICY.md`. What it names depends on
  whether you started from an existing reproducer:
  - Rewriting/adapting an existing generator: keep the provenance of the
    original and append the adapting model's identifier, e.g. "Generated with
    OpenAI Codex, adapted with <model-id> to follow the scapy-pcap
    conventions."
  - Writing a new generator from scratch: state what the trace exercises and
    name the model that wrote it, e.g. "Generates a <protocol> trace for
    <behavior under test>. Written with <model-id> using Scapy." There is no
    prior provenance to preserve — do not invent one.

## Pass the pre-commit checks

- The finished script must pass the repo's pre-commit checks, which CI runs,
  too. Run them on the generator with
  `pre-commit run --files <name>.pcap.py` and commit any changes the
  formatting hooks make. Reformatting only touches the Python source; it does
  not change the generated trace bytes, so no need to regenerate afterwards.

## Verify before finishing

Follow `assets/verification.md` for the commands and exceptions. In short:

1. Run the script twice; `sha256sum` of the output must match.
2. Sanity-check the structure with `rdpcap` (packet count, TCP flags,
   payloads, timestamps).
3. Cross-check with `tshark`, an independent dissector: no malformed packets
   or expert errors (unless they are the point of the test), and a clean
   teardown for TCP flows that are not intentionally partial.
4. Confirm the IP/TCP/UDP checksums are valid with tshark's checksum
   validation enabled.

See the templates in this skill's `assets/` directory for a minimal starting
point: `assets/template-tcp.pcap.py` for a TCP flow (handshake, direction-aware
`pkt()` helper, teardown) and `assets/template-udp.pcap.py` for a
connectionless/single-packet trace.
