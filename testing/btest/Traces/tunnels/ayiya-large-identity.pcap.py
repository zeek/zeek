#!/usr/bin/env python3
"""
Generate ayiya-large-identity.pcap: a single AYIYA packet whose identity-length
nibble is 8, encoding a 256 octet identity field (1 << 8).

The AYIYA analyzer used to store this length in a uint8_t, so 256 wrapped to 0
and the inner packet was forwarded from an offset still inside the AYIYA header.
The inner IPv6/UDP packet here only parses correctly if the full 8 + 256 + 20
byte header is stripped first.

Adapted with Claude Sonnet 5.5 (Anthropic) to be reproducible.
"""

from pathlib import Path

from scapy.all import IP, UDP, Ether, IPv6, Raw, wrpcap

AYIYA_PORT = 5072

BASE_TIME = 1_700_000_000.0

# idlen nibble = 8 -> identity_len = 1 << 8 = 256
IDLEN_NIBBLE = 8
IDENTITY_LEN = 1 << IDLEN_NIBBLE
# siglen nibble = 5 -> signature_len = 5 * 4 = 20 (and matches DetectProtocol)
SIGNATURE_LEN = 5 * 4
NEXT_HEADER_IPV6 = 41  # IPPROTO_IPV6


def ayiya_payload():
    # byte0: idlen<<4 | idtype(1), byte1: 0x52, byte2: 0x11 (opcode 1 = forward),
    # byte3: next header, bytes4-7: epoch time.
    header = bytes([(IDLEN_NIBBLE << 4) | 0x01, 0x52, 0x11, NEXT_HEADER_IPV6])
    header += b"\x00\x00\x00\x00"
    identity = b"\x00" * IDENTITY_LEN
    signature = b"\x00" * SIGNATURE_LEN
    inner = (
        IPv6(src="fd00::1", dst="fd00::2", hlim=64)
        / UDP(sport=40000, dport=40001)
        / Raw(b"zeek")
    )
    return header + identity + signature + bytes(inner)


def main():
    pkt = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=12345, dport=AYIYA_PORT)
        / Raw(ayiya_payload())
    )

    pkt.time = BASE_TIME

    wrpcap(str(Path(__file__).with_suffix("")), [pkt])


if __name__ == "__main__":
    main()
