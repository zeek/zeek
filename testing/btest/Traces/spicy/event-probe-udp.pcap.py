#!/usr/bin/env python3
"""Generate event-probe-udp.pcap: three UDP datagrams, each one complete message.

Each datagram carries an eight-byte network-order length, that many one-byte
items, and a three-byte tail, as the EventProbe Spicy analyzer parses them. The
first and second datagrams come from the originator to UDP port 9999, and the
third comes back from the responder, so each parse is independent and the
direction reaches the event.

Run this script to regenerate the trace; btests read the committed trace.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from scapy.all import IP, UDP, Ether, Raw, wrpcap

CLIENT = ("02:00:00:00:00:01", "192.0.2.1", 40000)
SERVER = ("02:00:00:00:00:02", "198.51.100.2", 9999)


def message(items: bytes, tail: bytes) -> bytes:
    """Encode one EventProbe message: a length, the items it counts, and a tail."""
    return struct.pack("!Q", len(items)) + items + tail


def datagram(src, dst, payload: bytes, time: int):
    pkt = (
        Ether(src=src[0], dst=dst[0])
        / IP(src=src[1], dst=dst[1], ttl=64)
        / UDP(sport=src[2], dport=dst[2])
        / Raw(load=payload)
    )
    # Deterministic timestamps keep the capture byte-for-byte reproducible.
    pkt.time = time
    return pkt


def build():
    return [
        datagram(CLIENT, SERVER, message(b"AB", b"END"), 0),
        datagram(CLIENT, SERVER, message(b"Z", b"QRS"), 1),
        datagram(SERVER, CLIENT, message(b"", b"ABC"), 2),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_suffix("").with_suffix(".pcap"))
    args = parser.parse_args()
    wrpcap(str(args.output), build())


if __name__ == "__main__":
    main()
