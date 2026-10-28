#!/usr/bin/env python3
"""Generate event-probe-two-ports.pcap: UDP datagrams for two analyzers with one parser name.

Two Spicy analyzers define the parser `EventProbe::Message` with different layouts and
listen on different UDP ports. Datagrams to port 9998 carry an eight-byte length, that
many one-byte items, and a three-byte tail. Datagrams to port 9999 carry the same length
and items, and a two-byte tail. Each port receives two datagrams from one originator, so
every parse is independent.

This script was written with the help of Claude Sonnet 5.5 (an LLM).

Run this script to regenerate the trace; btests read the committed trace.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from scapy.all import IP, UDP, Ether, FieldLenField, Packet, StrField, StrLenField, wrpcap

CLIENT = ("02:00:00:00:00:01", "192.0.2.1", 40000)
SERVER = ("02:00:00:00:00:02", "198.51.100.2")
FIRST_PORT = 9998
SECOND_PORT = 9999


class Message(Packet):
    """A length, that many items, and the tail that fills the rest of the datagram."""

    name = "EventProbe message"
    fields_desc = [
        FieldLenField("length", None, length_of="items", fmt="Q"),
        StrLenField("items", b"", length_from=lambda pkt: pkt.length),
        StrField("tail", b""),
    ]


def datagram(port: int, payload: Message, time: int):
    pkt = (
        Ether(src=CLIENT[0], dst=SERVER[0])
        / IP(src=CLIENT[1], dst=SERVER[1], ttl=64)
        / UDP(sport=CLIENT[2], dport=port)
        / payload
    )
    # Deterministic timestamps keep the capture byte-for-byte reproducible.
    pkt.time = time
    return pkt


def build():
    return [
        datagram(FIRST_PORT, Message(items=b"AB", tail=b"END"), 0),
        datagram(SECOND_PORT, Message(items=b"AB", tail=b"EN"), 1),
        datagram(FIRST_PORT, Message(items=b"Z", tail=b"QRS"), 2),
        datagram(SECOND_PORT, Message(items=b"", tail=b"QR"), 3),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_suffix("").with_suffix(".pcap"))
    args = parser.parse_args()
    wrpcap(str(args.output), build())


if __name__ == "__main__":
    main()
