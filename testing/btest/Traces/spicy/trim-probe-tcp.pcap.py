#!/usr/bin/env python3
"""Generate trim-probe-tcp.pcap: one TCP connection carrying a long TrimProbe frame in small segments.

A frame is a four-byte head, an eight-byte network-order byte count, that many
bytes of two-byte items, and a three-byte tail. The originator sends it in
segments of five bytes, so the parser suspends and resumes many times while it
consumes the vector, and the responder never sends.

Run this script to regenerate the trace; btests read the committed trace.

Generates a TCP trace for incremental Spicy parsing with input trimming.
Written with Claude Sonnet 5.5 using Scapy.
"""

import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 40000
SERVER_PORT = 9996
BASE_TIME = 1_700_000_000.0
ITEM_COUNT = 40
SEGMENT_SIZE = 5


def frame():
    """Encode one frame: a head, the byte count of the items, the items, and a tail."""
    items = b"".join(
        bytes([ord("a") + i % 26, ord("A") + i % 26]) for i in range(ITEM_COUNT)
    )
    return b"HEAD" + struct.pack("!Q", len(items)) + items + b"END"


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


def build_packets():
    client_seq, server_seq = 1000, 2000
    packets = [
        pkt(True, client_seq, 0, "S"),
        pkt(False, server_seq, client_seq + 1, "SA"),
        pkt(True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    data = frame()
    for offset in range(0, len(data), SEGMENT_SIZE):
        payload = data[offset : offset + SEGMENT_SIZE]
        packets.append(pkt(True, client_seq, server_seq, "PA", payload))
        client_seq += len(payload)

    packets.append(pkt(True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))
    return packets


def main():
    packets = build_packets()
    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001
    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
