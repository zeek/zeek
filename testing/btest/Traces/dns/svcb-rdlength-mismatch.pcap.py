#!/usr/bin/env python3
"""
Generate dns-svcb-rdlength-mismatch.pcap with a DNS SVCB response where
RDLENGTH is shorter than the minimum valid SVCB RDATA size.
"""

import struct
from pathlib import Path

from scapy.all import IP, UDP, Ether, Raw, wrpcap


def build_question():
    qname = b"\x03www\x07example\x03com\x00"
    return qname + struct.pack("!HH", 64, 1)


def build_response_payload():
    question = build_question()
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 1)

    # RDLENGTH=2 is malformed for SVCB (minimum is 3 bytes).
    answer_fixed = b"\xc0\x0c" + struct.pack("!HHIH", 64, 1, 300, 2)
    answer_rdata = b"\x00\x01"

    # Include an OPT RR so bytes follow the malformed answer in the message.
    opt_rr = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)

    return header + question + answer_fixed + answer_rdata + opt_rr


def main():
    question = build_question()
    query_payload = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
    response_payload = build_response_payload()

    packets = [
        Ether()
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / UDP(sport=1234, dport=53)
        / Raw(load=query_payload),
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=53, dport=1234)
        / Raw(load=response_payload),
    ]

    out = Path(__file__).resolve().parent.parent / "dns-svcb-rdlength-mismatch.pcap"
    wrpcap(str(out), packets)
    print(f"Wrote 2 packets to {out}")


if __name__ == "__main__":
    main()
