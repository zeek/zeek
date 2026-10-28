#!/usr/bin/env python3
"""Generate frame-probe-tcp.pcap: three TCP connections carrying FrameProbe frames.

A frame is a one-byte kind, an eight-byte network-order count, one more one-byte
cell than the count says, and a two-byte label. The first connection splits the originator's frame
inside the header, the body, and the trailer, and the responder answers with a
whole frame in one segment. The second sends a frame of kind zero. The third
ends in the middle of the body.

Run this script to regenerate the trace; btests read the committed trace.

Generates a TCP trace for incremental Spicy parsing with event consumers.
Written with Claude Sonnet 5.5 using Scapy.
"""

import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
SERVER_PORT = 9997
BASE_TIME = 1_700_000_000.0


def frame(kind, cells, label):
    """Encode one frame: a kind, the number of cells less one, the cells, and a label."""
    assert cells
    return bytes([kind]) + struct.pack("!Q", len(cells) - 1) + cells + label


def connection(client_port, segments):
    """Build one connection from (is_orig, payload) segments, with a clean teardown."""

    def pkt(is_orig, seq, ack, flags, payload=b""):
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

    client_seq, server_seq = 1000, 2000
    packets = [
        pkt(True, client_seq, 0, "S"),
        pkt(False, server_seq, client_seq + 1, "SA"),
        pkt(True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    for is_orig, payload in segments:
        if is_orig:
            packets.append(pkt(True, client_seq, server_seq, "PA", payload))
            client_seq += len(payload)
        else:
            packets.append(pkt(False, server_seq, client_seq, "PA", payload))
            server_seq += len(payload)

    packets.append(pkt(True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))
    return packets


def build_packets():
    first = frame(7, b"xy", b"ab")
    # Split inside the count, inside the cells, and before the last label byte.
    split = [
        (True, first[:4]),
        (True, first[4:10]),
        (True, first[10:12]),
        (True, first[12:]),
    ]
    split.append((False, frame(9, b"r", b"ZZ")))

    return (
        connection(40000, split)
        + connection(40001, [(True, frame(0, b"q", b"cd"))])
        + connection(40002, [(True, frame(5, b"abc", b"ef")[:11])])
    )


def main():
    packets = build_packets()
    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001
    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
