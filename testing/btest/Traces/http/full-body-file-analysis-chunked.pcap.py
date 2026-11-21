#!/usr/bin/env python3
"""multipart responses with chunked transfer coding.

HTTP doesn't remove chunked transfer coding from multipart or message/*
bodies. Each connection carries one GET and one response with the same
PE-like body:

  * port 40001: application/octet-stream with Content-Length (control),
  * port 40002: multipart/mixed, chunked, in three chunks with an upper-case
    size, a chunk extension and a trailer field,
  * port 40003: multipart/mixed, chunked, with 20 leading zeros on each chunk
    size and a bare LF ending each chunk size and chunk,
  * port 40004: gzip-compressed multipart/mixed, chunked, in two chunks,
  * port 40005: multipart/mixed, chunked, with a space before the chunk size,
  * port 40006: multipart/mixed, chunked, with a 0x prefix on the chunk size.

Lenient clients may accept the last two chunk sizes.

The boundary never occurs in the body, so MIME parsing hides all of it.
Each response is on its own connection, since HTTP doesn't find the end of
a chunked multipart body.

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

BODY = (
    b"MZ\x90\x00\x03\x00\x00\x00"
    + b"\x00" * 8
    + b"This program cannot be run in DOS mode.\r\r\n$"
    + b"\x00" * 7
    + b"PE\x00\x00"
    + bytes(range(256))
    + b"\r\n"
)

# mtime=0 keeps the compressed bytes reproducible.
GZIP_BODY = gzip.compress(BODY, mtime=0)

REQUEST = b"GET /a HTTP/1.1\r\nHost: 192.0.2.2\r\n\r\n"
MULTIPART = b"Content-Type: multipart/mixed; boundary=never\r\n"


def chunked(parts, eol=b"\r\n", size=b"%x", trailer=b""):
    out = b""
    for part in parts:
        out += size % len(part) + eol + part + eol
    return out + b"0" + eol + trailer + eol


RESPONSES = [
    b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
    b"Content-Length: %d\r\n\r\n%s" % (len(BODY), BODY),
    b"HTTP/1.1 200 OK\r\n"
    + MULTIPART
    + b"Transfer-Encoding: chunked\r\n\r\n"
    + chunked(
        [BODY[:100], BODY[100:101], BODY[101:]],
        size=b"%X;name=value",
        trailer=b"X-Trailer: 1\r\n",
    ),
    b"HTTP/1.1 200 OK\r\n"
    + MULTIPART
    + b"Transfer-Encoding: chunked\r\n\r\n"
    + chunked([BODY[:50], BODY[50:]], eol=b"\n", size=b"0" * 20 + b"%x"),
    b"HTTP/1.1 200 OK\r\n"
    + MULTIPART
    + b"Content-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"
    + chunked([GZIP_BODY[:20], GZIP_BODY[20:]]),
    b"HTTP/1.1 200 OK\r\n"
    + MULTIPART
    + b"Transfer-Encoding: chunked\r\n\r\n"
    + chunked([BODY], size=b" %x"),
    b"HTTP/1.1 200 OK\r\n"
    + MULTIPART
    + b"Transfer-Encoding: chunked\r\n\r\n"
    + chunked([BODY], size=b"0x%x"),
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


def connection(client_port, response):
    c, s = 1000, 2000
    req_end, resp_end = c + 1 + len(REQUEST), s + 1 + len(response)
    return [
        pkt(client_port, True, c, 0, "S"),
        pkt(client_port, False, s, c + 1, "SA"),
        pkt(client_port, True, c + 1, s + 1, "A"),
        pkt(client_port, True, c + 1, s + 1, "PA", REQUEST),
        pkt(client_port, False, s + 1, req_end, "PA", response),
        pkt(client_port, True, req_end, resp_end, "A"),
        pkt(client_port, True, req_end, resp_end, "FA"),
        pkt(client_port, False, resp_end, req_end + 1, "FA"),
        pkt(client_port, True, req_end + 1, resp_end + 1, "A"),
    ]


def build_packets():
    packets = []
    for index, response in enumerate(RESPONSES):
        packets += connection(40001 + index, response)
    return packets


def main():
    packets = build_packets()

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
