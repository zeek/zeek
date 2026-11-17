#!/usr/bin/env python3
"""Requests with a multipart Content-Type but no length, then other traffic.

A request without Content-Length or Transfer-Encoding has no body. Each
connection carries one such request with a multipart/form-data Content-Type,
followed by data that isn't part of it:

  * port 40001: a CONNECT request, a 200 reply and tunneled bytes in both
    directions,
  * port 40002: a WebSocket Upgrade request, a 101 reply and WebSocket
    frames in both directions.

Written with claude-opus-5-5 using Scapy (disclose AI assistance per
AI_POLICY.md).
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
SERVER_PORT = 80
BASE_TIME = 1_700_000_000.0

MULTIPART = b"Content-Type: multipart/form-data; boundary=x\r\n"

CONVERSATIONS = [
    [
        (
            True,
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
            + MULTIPART
            + b"\r\n",
        ),
        (False, b"HTTP/1.1 200 OK\r\n\r\n"),
        (True, b"\x16\x03\x01\x00\x05" + b"C" * 5),
        (False, b"\x16\x03\x03\x00\x05" + b"S" * 5),
    ],
    [
        (
            True,
            b"GET /ws HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\n"
            b"Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" + MULTIPART + b"\r\n",
        ),
        (
            False,
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
            b"Upgrade: websocket\r\n"
            b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        ),
        # A masked text frame "Hello" and an unmasked one in reply.
        (True, b"\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58"),
        (False, b"\x81\x05Hello"),
    ],
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


def connection(client_port, conversation):
    c, s = 1000, 2000
    packets = [
        pkt(client_port, True, c, 0, "S"),
        pkt(client_port, False, s, c + 1, "SA"),
        pkt(client_port, True, c + 1, s + 1, "A"),
    ]
    c += 1
    s += 1
    for is_orig, data in conversation:
        if is_orig:
            packets.append(pkt(client_port, True, c, s, "PA", data))
            c += len(data)
        else:
            packets.append(pkt(client_port, False, s, c, "PA", data))
            s += len(data)
    packets += [
        pkt(client_port, True, c, s, "FA"),
        pkt(client_port, False, s, c + 1, "FA"),
        pkt(client_port, True, c + 1, s + 1, "A"),
    ]
    return packets


def build_packets():
    packets = []
    for index, conversation in enumerate(CONVERSATIONS):
        packets += connection(40001 + index, conversation)
    return packets


def main():
    packets = build_packets()

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
