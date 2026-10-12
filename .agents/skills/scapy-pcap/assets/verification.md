# Verifying a generated trace

Detailed checks for the "Verify before finishing" list in `SKILL.md`.

1. Run the script twice and confirm identical bytes — `sha256sum` must match
   across runs (reproducibility). This applies to a plain `<name>.pcap` just as
   much as a `<name>.pcap.gz`; a differing hash means a timestamp, nonce, or
   other nondeterministic value leaked in (see "Deterministic timestamps" in
   `SKILL.md`).
2. Sanity-check structure independently of Zeek — the point of a reproducer is
   not to trust Zeek's own parser:
   ```python
   from scapy.all import rdpcap, Raw
   ps = rdpcap("<name>.pcap")
   # assert packet count, TCP flags on the handshake, payload contents,
   # direction counts, first/last timestamps
   ```
   Note that `rdpcap` only re-parses the bytes Scapy itself just wrote, so it
   confirms almost nothing about whether the L7 payload is well-formed — Scapy
   will happily read back a nonsense command code it wrote.
3. Cross-check with `tshark` (a genuinely independent dissector) — treat this
   as required, not optional, for any trace with an application-layer payload.
   It catches malformed payloads Scapy misses. Read a plain trace directly, or
   a compressed one over stdin:
   ```
   tshark -r <name>.pcap
   zcat <name>.pcap.gz | tshark -r -
   ```
   Scan the summary column for `[Malformed Packet]` / `unknown` and check the
   expert info (`-Y "_ws.malformed || _ws.expert.severity==error"` should be
   empty; `-T fields -e <proto>.<field>` to confirm per-message fields). If a
   real dissector flags the trace, pick protocol field values it accepts —
   e.g. a valid command code, not a reserved/unknown one that renders every
   packet malformed. Also make sure the message type you pick actually
   exercises the behavior under test without a side effect that undoes it.

   For a TCP flow, also check the teardown, unless the flow is intentionally
   partial: the last three packets should be `[FIN, ACK]` / `[FIN, ACK]` /
   `[ACK]` with no `tcp.analysis.flags`.

   **Exception — intentionally malformed traces:** when the trace is *testing
   Zeek's handling of invalid input* (truncated headers, unknown opcodes,
   out-of-range field values, etc.), tshark dissector errors are expected and
   intentional. In that case, confirm that tshark flags *exactly* the packets
   you intended to be malformed and none of the surrounding framing
   (handshake, teardown, surrounding well-formed messages). Do not "fix" the
   payload to satisfy tshark — the bad input is the point of the test.
4. Confirm the IP/TCP/UDP checksums are valid. Scapy computes them at write
   time, so a trace built purely with the high-level API passes — but verify
   it, because a checksum or length field you set by hand, a packet you copied
   and mutated, or a transport header hand-rolled in a `Raw` blob can carry a
   stale value, and Zeek may silently drop a bad-checksum packet (see
   `ignore_checksums`, and `C`/`c` in conn history). tshark does NOT validate
   checksums by default, so enable it explicitly:
   ```
   tshark -r <name>.pcap -o ip.check_checksum:TRUE \
       -o tcp.check_checksum:TRUE -o udp.check_checksum:TRUE \
       -Y 'ip.checksum.status=="Bad" || tcp.checksum.status=="Bad" || udp.checksum.status=="Bad"'
   ```
   That filter should print nothing — any row is a bad checksum. (Exception: a
   trace that *tests* bad-checksum handling wants specific packets to fail
   here; as with malformed input, confirm it is exactly the packets you
   intended.)
