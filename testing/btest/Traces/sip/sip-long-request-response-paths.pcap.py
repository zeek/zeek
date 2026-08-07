#! /usr/bin/env python3
"""
Generates a pcap file with a SIP session containing a configurable length path
"""

import argparse
from pathlib import Path

from scapy.all import IP, UDP, Raw, wrpcap

SRC = "192.0.2.10"
DST = "198.51.100.20"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate a pcap of a fake SIP session with scapy."
    )

    parser.add_argument(
        "-l",
        "--length",
        type=int,
        default=100,
        help="Length of VIA path in SIP session (default: 100)",
    )

    return parser.parse_args()


def request_payload(length: int) -> bytes:
    via_headers = b""
    for i in range(length):
        via_value = ("SIP/2.0/UDP " + ("a" * 900) + f"{i:04d}").encode()
        via_headers += (
            b"Via: " + via_value + b";branch=z9hG4bK" + str(i).encode() + b"\r\n"
        )
    return (
        b"OPTIONS sip:bob@example.com SIP/2.0\r\n"
        + via_headers
        + b"From: <sip:alice@example.com>;tag=1\r\n"
        + b"To: <sip:bob@example.com>\r\n"
        + b"Call-ID: path-growth@example.com\r\n"
        + b"CSeq: 1 OPTIONS\r\n"
        + b"Content-Length: 0\r\n"
        + b"\r\n"
    )


def response_payload(length: int) -> bytes:
    via_headers = b""
    for i in range(length):
        via_value = ("SIP/2.0/UDP " + ("a" * 900) + f"{i:04d}").encode()
        via_headers += (
            b"Via: " + via_value + b";branch=z9hG4bK" + str(i).encode() + b"\r\n"
        )
    return (
        b"SIP/2.0 200 OK\r\n"
        + via_headers
        + b"From: <sip:alice@example.com>;tag=1\r\n"
        + b"To: <sip:bob@example.com>;tag=2\r\n"
        + b"Call-ID: path-growth@example.com\r\n"
        + b"CSeq: 1 OPTIONS\r\n"
        + b"Content-Length: 0\r\n"
        + b"\r\n"
    )


def build(length: int) -> list:
    pkts = [
        IP(src=SRC, dst=DST)
        / UDP(sport=50600, dport=5060)
        / Raw(request_payload(length)),
        IP(src=DST, dst=SRC)
        / UDP(sport=5060, dport=50600)
        / Raw(response_payload(length)),
    ]
    return pkts


if __name__ == "__main__":
    args = parse_args()
    outfile = Path(__file__).with_suffix("")
    pkts = build(args.length)
    wrpcap(str(outfile), pkts)
