#!/usr/bin/env python3
"""Brotli-compressed responses with the same PE-like body.

Each response is on its own connection, uses Content-Encoding: br and
Content-Length, and is split into 100 byte TCP segments:

  * port 40001: application/octet-stream (control, a body delivered as-is),
  * port 40002: multipart/mixed whose body is the PE-like data before its
    only boundary, so MIME parsing ignores it and the body is delivered
    line by line.

Requires the "brotli" Python module for compression; its output is
deterministic for a fixed quality setting.

Written with claude-opus-5-5 using Scapy (disclose AI assistance per
AI_POLICY.md).
"""

from pathlib import Path

import brotli
from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
SERVER_PORT = 80
BASE_TIME = 1_700_000_000.0
SEGMENT_SIZE = 100

# The CRLF lines and the closing boundary make the multipart body line-delivered.
BODY = (
    b"MZ\x90\x00"
    + b"\x00" * 60
    + b"PE\x00\x00\r\n"
    + bytes(range(256)) * 4
    + b"\r\n--b--\r\n"
)
COMPRESSED = brotli.compress(BODY, quality=11)

REQUEST = b"GET /a HTTP/1.1\r\nHost: 192.0.2.2\r\n\r\n"


def response(content_type):
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Encoding: br\r\n"
        b"Content-Length: %d\r\n\r\n%s" % (content_type, len(COMPRESSED), COMPRESSED)
    )


RESPONSES = [
    response(b"application/octet-stream"),
    response(b"multipart/mixed; boundary=b"),
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


def connection(client_port, resp):
    c, s = 1001, 2001
    packets = [
        pkt(client_port, True, c - 1, 0, "S"),
        pkt(client_port, False, s - 1, c, "SA"),
        pkt(client_port, True, c, s, "A"),
        pkt(client_port, True, c, s, "PA", REQUEST),
    ]
    c += len(REQUEST)
    for i in range(0, len(resp), SEGMENT_SIZE):
        segment = resp[i : i + SEGMENT_SIZE]
        packets.append(pkt(client_port, False, s, c, "PA", segment))
        s += len(segment)
    # The client closes the connection after the response.
    packets += [
        pkt(client_port, True, c, s, "FA"),
        pkt(client_port, False, s, c + 1, "FA"),
        pkt(client_port, True, c + 1, s + 1, "A"),
    ]
    return packets


def build_packets():
    packets = []
    for index, resp in enumerate(RESPONSES):
        packets += connection(40001 + index, resp)
    return packets


def main():
    packets = build_packets()

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
