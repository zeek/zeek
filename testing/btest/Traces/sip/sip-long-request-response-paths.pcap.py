#! /usr/bin/env python3
"""
Generates a raw-IPv4 pcap file with a SIP session (one request and one
response) whose Via header path is VIA_COUNT entries long.

Adapted with Claude Sonnet 5.5 (Anthropic): the path length is now the constant
VIA_COUNT = 10, which reproduces the committed trace (the previous default of
100 made the UDP payload exceed 65535 bytes, so the script failed), packets
carry fixed timestamps, and the output is written beside the script.
"""

from pathlib import Path

from scapy.all import IP, UDP, Raw, wrpcap

SRC = "192.0.2.10"
DST = "198.51.100.20"

BASE_TIME = 1_700_000_000.0

# Each Via header is ~940 bytes, so the whole message has to stay well below the
# 65535 byte UDP limit.
VIA_COUNT = 10


def via_headers(count: int) -> bytes:
    headers = b""
    for i in range(count):
        via_value = ("SIP/2.0/UDP " + ("a" * 900) + f"{i:04d}").encode()
        headers += b"Via: " + via_value + b";branch=z9hG4bK" + str(i).encode() + b"\r\n"
    return headers


def request_payload(count: int) -> bytes:
    return (
        b"OPTIONS sip:bob@example.com SIP/2.0\r\n"
        + via_headers(count)
        + b"From: <sip:alice@example.com>;tag=1\r\n"
        + b"To: <sip:bob@example.com>\r\n"
        + b"Call-ID: path-growth@example.com\r\n"
        + b"CSeq: 1 OPTIONS\r\n"
        + b"Content-Length: 0\r\n"
        + b"\r\n"
    )


def response_payload(count: int) -> bytes:
    return (
        b"SIP/2.0 200 OK\r\n"
        + via_headers(count)
        + b"From: <sip:alice@example.com>;tag=1\r\n"
        + b"To: <sip:bob@example.com>;tag=2\r\n"
        + b"Call-ID: path-growth@example.com\r\n"
        + b"CSeq: 1 OPTIONS\r\n"
        + b"Content-Length: 0\r\n"
        + b"\r\n"
    )


def build(count: int) -> list:
    return [
        IP(src=SRC, dst=DST)
        / UDP(sport=50600, dport=5060)
        / Raw(request_payload(count)),
        IP(src=DST, dst=SRC)
        / UDP(sport=5060, dport=50600)
        / Raw(response_payload(count)),
    ]


if __name__ == "__main__":
    pkts = build(VIA_COUNT)
    for index, p in enumerate(pkts):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), pkts)
