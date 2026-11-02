#!/usr/bin/env python3
"""Generate an SMTP trace that exceeds MIME::max_header_bytes (65536).

A single SMTP session delivers one mail header ("Subject:") that is folded
across many continuation lines (each line is a single space + "x", i.e. two
header bytes). Each continuation feeds MIME_Entity::ContHeader(), which
accumulates into MIME_Multiline::total_bytes. Once that reaches the 65536-byte
MIME::max_header_bytes cap, Zeek raises the "exceeded_mime_max_header_bytes"
weird and marks the connection history with 'X' (analyzer limit reached).

The "Subject: CVE-CANDIDATE" line contributes 22 bytes, so total_bytes walks
22, 24, ... and lands on exactly 65536 after 32757 appended continuation
lines; the next continuation line trips the cap and the weird reports 65536.
CONTINUATION_LINES is kept comfortably above that 32758-line threshold.

Originally AI generated (reads an external .eml); rewritten with
Claude Opus 4.8 to be self-contained and use Scapy per AI_POLICY.md. The trace
is highly repetitive, so it is written as a reproducible gzip.
"""

import gzip
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.10"
SERVER = "192.0.2.20"
CLIENT_PORT = 54321
SERVER_PORT = 25  # SMTP
BASE_TIME = 1_700_000_000.0

# Well above the 32758-line trigger threshold (see module docstring).
CONTINUATION_LINES = 40_000

CRLF = b"\r\n"

# TCP segments stay comfortably under a typical MTU.
CHUNK = 1400


def pkt(is_orig, seq, ack, flags, payload=b""):
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, CLIENT_PORT, SERVER_PORT
        eth_src, eth_dst = "02:00:00:00:00:01", "02:00:00:00:00:02"
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, CLIENT_PORT
        eth_src, eth_dst = "02:00:00:00:00:02", "02:00:00:00:00:01"
    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    return p


def build_mail_data():
    """The RFC 2822 message Zeek's MIME parser sees after the SMTP DATA verb."""
    lines = [
        b"From: exploit@attacker.evil",
        b"Subject: CVE-CANDIDATE",  # 22 bytes -> total_bytes starts even
    ]
    # Folded continuation lines: a single leading space marks linear whitespace
    # (is_lws), routing each line to ContHeader() -> MIME_Multiline::append().
    lines.extend([b" x"] * CONTINUATION_LINES)
    lines.extend(
        [
            b"",  # end of headers
            b"This is the body.",
            b".",  # SMTP DATA terminator
        ]
    )
    return CRLF.join(lines) + CRLF


def build_packets():
    client_seq, server_seq = 1000, 2000
    packets = [
        pkt(True, client_seq, 0, "S"),
        pkt(False, server_seq, client_seq + 1, "SA"),
        pkt(True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    # (is_orig, payload) in dialog order. The large mail body is chunked below.
    dialog = [
        (False, b"220 mail.target.example ESMTP ready" + CRLF),
        (True, b"EHLO attacker.evil" + CRLF),
        (False, b"250-mail.target.example Hello" + CRLF + b"250 OK" + CRLF),
        (True, b"MAIL FROM:<exploit@attacker.evil>" + CRLF),
        (False, b"250 OK" + CRLF),
        (True, b"RCPT TO:<victim@target.example>" + CRLF),
        (False, b"250 OK" + CRLF),
        (True, b"DATA" + CRLF),
        (False, b"354 Start mail input; end with <CRLF>.<CRLF>" + CRLF),
        (True, build_mail_data()),
        (False, b"250 OK: message accepted" + CRLF),
        (True, b"QUIT" + CRLF),
        (False, b"221 Bye" + CRLF),
    ]

    for is_orig, payload in dialog:
        offset = 0
        while offset < len(payload):
            chunk = payload[offset : offset + CHUNK]
            offset += len(chunk)
            if is_orig:
                packets.append(pkt(True, client_seq, server_seq, "PA", chunk))
                client_seq += len(chunk)
                packets.append(pkt(False, server_seq, client_seq, "A"))
            else:
                packets.append(pkt(False, server_seq, client_seq, "PA", chunk))
                server_seq += len(chunk)
                packets.append(pkt(True, client_seq, server_seq, "A"))

    # Clean FIN/ACK teardown, client-initiated (a FIN consumes one seq).
    packets.append(pkt(True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))
    return packets


def main():
    packets = build_packets()

    # Assign reproducible, monotonically increasing timestamps.
    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    # Highly compressible repetitive trace -> reproducible gzip (mtime=0).
    with gzip.GzipFile(Path(__file__).with_suffix(".gz"), "wb", mtime=0) as f:
        wrpcap(f, packets)


if __name__ == "__main__":
    main()
