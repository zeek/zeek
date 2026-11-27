#!/usr/bin/env python3
"""Responses that lose a TCP segment.

Each response is split into three segments and the middle one is missing
from the capture:

  * port 40001: multipart/mixed (control, the gap is reported and the body
    continues after it),
  * port 40002: gzip-compressed multipart/mixed (the body can't be
    decompressed past the gap),
  * port 40003: multipart/mixed with chunked transfer coding instead of
    Content-Length (the chunk framing is lost at the gap),
  * port 40004: gzip-compressed application/octet-stream, which isn't
    line-delivered (the body can't be decompressed past the gap).

The boundary never occurs in the body.

Written with claude-opus-5-5 using Scapy (disclose AI assistance per
AI_POLICY.md).
"""

import gzip
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
SERVER_PORT = 80
BASE_TIME = 1_700_000_000.0

BODY = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + bytes(range(256)) * 4

# mtime=0 keeps the compressed bytes reproducible.
GZIP_BODY = gzip.compress(BODY, mtime=0)

REQUEST = b"GET /a HTTP/1.1\r\nHost: 192.0.2.2\r\n\r\n"
MULTIPART = b"Content-Type: multipart/mixed; boundary=never\r\n"

RESPONSES = [
    (
        b"HTTP/1.1 200 OK\r\n" + MULTIPART + b"Content-Length: %d\r\n\r\n" % len(BODY),
        BODY,
    ),
    (
        b"HTTP/1.1 200 OK\r\n"
        + MULTIPART
        + b"Content-Encoding: gzip\r\nContent-Length: %d\r\n\r\n" % len(GZIP_BODY),
        GZIP_BODY,
    ),
    (
        b"HTTP/1.1 200 OK\r\n" + MULTIPART + b"Transfer-Encoding: chunked\r\n\r\n",
        b"%x\r\n%s\r\n0\r\n\r\n" % (len(BODY), BODY),
    ),
    (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Encoding: gzip\r\nContent-Length: %d\r\n\r\n" % len(GZIP_BODY),
        GZIP_BODY,
    ),
]


def pkt(client_port, is_orig, seq, ack, flags, payload=b""):
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, client_port, SERVER_PORT
        eth_src, eth_dst = "02:00:00:00:00:01", "02:00:00:00:00:02"
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, client_port
        eth_src, eth_dst = "02:00:00:00:00:02", "02:00:00:00:00:01"
    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    return p


def connection(client_port, headers, body):
    c, s = 1001, 2001
    third = len(body) // 3
    segments = [headers + body[:third], body[third : 2 * third], body[2 * third :]]
    packets = [
        pkt(client_port, True, c - 1, 0, "S"),
        pkt(client_port, False, s - 1, c, "SA"),
        pkt(client_port, True, c, s, "A"),
        pkt(client_port, True, c, s, "PA", REQUEST),
    ]
    c += len(REQUEST)
    for index, segment in enumerate(segments):
        # The middle segment is lost.
        if index != 1:
            packets.append(pkt(client_port, False, s, c, "PA", segment))
        s += len(segment)
    packets += [
        pkt(client_port, True, c, s, "A"),
        pkt(client_port, True, c, s, "FA"),
        pkt(client_port, False, s, c + 1, "FA"),
        pkt(client_port, True, c + 1, s + 1, "A"),
    ]
    return packets


def build_packets():
    packets = []
    for index, (headers, body) in enumerate(RESPONSES):
        packets += connection(40001 + index, headers, body)
    return packets


def main():
    packets = build_packets()

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
