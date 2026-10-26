#!/usr/bin/env python3
"""Compact-peer tracker replies that expose retained event values.

Each of the RESPONSES completed tracker exchanges carries a maximum-sized
response holding 329 distinct compact peers, then closes its TCP connection.
The BitTorrent tracker analyzer retains the peer values in a table even when
no event consumes them, so replaying many such exchanges grows memory without
bound.

Generated with OpenAI Codex, adapted with Claude Opus 4.8 to use Scapy.
"""

from __future__ import annotations

import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
SERVER_PORT = 6969
CLIENT_PORT_BASE = 40_000
RESPONSES = 10
BASE_TIME = 1_700_000_000.0

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


def pkt(client_port, is_orig, seq, ack, flags, payload=b""):
    """Build one deterministic Ethernet/IPv4/TCP packet for a flow."""
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, client_port, SERVER_PORT
        eth_src, eth_dst = CLIENT_MAC, SERVER_MAC
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, client_port
        eth_src, eth_dst = SERVER_MAC, CLIENT_MAC
    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    return p


def compact_peers():
    """Return 329 distinct six-byte IPv4/port compact-peer records."""
    return b"".join(
        struct.pack("!IH", 0x0A000001 + index, 1024 + index) for index in range(329)
    )


def tracker_request():
    """Return one valid tracker announce request."""
    return (
        b"GET /announce?info_hash=x HTTP/1.1\r\n"
        b"Host: tracker.test\r\n"
        b"Connection: close\r\n\r\n"
    )


def tracker_response():
    """Return a maximum-sized response populated with compact peers."""
    peers = compact_peers()
    body = b"d5:peers" + str(len(peers)).encode() + b":" + peers + b"e"
    response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + body
    if len(response) >= 2048:
        raise ValueError("tracker response exceeds the analyzer buffer")
    return response


def flow_packets(index, request, response):
    """Yield one completed tracker request/response TCP flow."""
    client_port = CLIENT_PORT_BASE + index
    client_seq, server_seq = 1000, 8000

    # SYN / SYN-ACK / ACK handshake.
    yield pkt(client_port, True, client_seq, 0, "S")
    yield pkt(client_port, False, server_seq, client_seq + 1, "SA")
    client_seq += 1
    yield pkt(client_port, True, client_seq, server_seq + 1, "A")
    server_seq += 1

    # Announce request and the compact-peer response.
    yield pkt(client_port, True, client_seq, server_seq, "PA", request)
    client_seq += len(request)
    yield pkt(client_port, False, server_seq, client_seq, "PA", response)
    server_seq += len(response)

    # Server closes (Connection: close); client FIN acks the response + FIN.
    yield pkt(client_port, False, server_seq, client_seq, "FA")
    server_seq += 1
    yield pkt(client_port, True, client_seq, server_seq, "FA")
    client_seq += 1
    yield pkt(client_port, False, server_seq, client_seq, "A")


def build_packets():
    """Build every tracker exchange in the capture."""
    request = tracker_request()
    response = tracker_response()
    packets = [
        packet
        for index in range(RESPONSES)
        for packet in flow_packets(index, request, response)
    ]
    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001
    return packets


def main():
    """Generate the compact-peer response capture."""
    packets = build_packets()
    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
