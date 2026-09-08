#!/usr/bin/env python3
"""Write a pcap containing a DNS reply with a WKS (Well Known Services) record.

WKS RDATA format (RFC 1035, section 3.4.2):
    +--+--+--+--+
    |    ADDRESS    |   32-bit IPv4 address
    +--+--+--+--+
    | PROTOCOL |         8-bit IP protocol number (e.g. 6 = TCP, 17 = UDP)
    +--+--+--+--+
    |   <BIT MAP>  ...   variable-length port bitmap; bit N set => port N in use
    +--+--+--+--+

Usage:
    python3 write_dns_wks_pcap.py
"""

import struct
from pathlib import Path

from scapy.all import IP, UDP, Raw, wrpcap


def encode_name(name: str) -> bytes:
    """Encode a domain name into DNS label format."""
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def wks_rdata(address: str, protocol: int, ports) -> bytes:
    """Build WKS RDATA: 4-byte address, 1-byte protocol, port bitmap."""
    addr_bytes = bytes(int(o) for o in address.split("."))
    if len(addr_bytes) != 4:
        raise ValueError("address must be IPv4 dotted-quad")

    # Bitmap large enough to hold the highest port; bit 0 is the most
    # significant bit of the first byte (network bit order).
    max_port = max(ports) if ports else 0
    bitmap = bytearray((max_port // 8) + 1)
    for p in ports:
        bitmap[p // 8] |= 0x80 >> (p % 8)

    return addr_bytes + struct.pack("!B", protocol) + bytes(bitmap)


def build_dns_reply() -> bytes:
    """Construct a DNS response message with a single WKS answer."""
    qname = "example.com"
    TYPE_A = 1
    TYPE_WKS = 11
    CLASS_IN = 1

    # --- Header ---
    txn_id = 0x1234
    flags = 0x8180  # QR=1 (response), RD=1, RA=1, rcode=0
    qdcount = 1
    ancount = 2  # WKS + A
    header = struct.pack("!HHHHHH", txn_id, flags, qdcount, ancount, 0, 0)

    # --- Question ---
    question = encode_name(qname) + struct.pack("!HH", TYPE_WKS, CLASS_IN)

    # --- Answer 1: WKS ---
    wks = wks_rdata("192.0.2.1", protocol=6, ports=[25, 80, 443])
    wks_answer = (
        encode_name(qname)
        + struct.pack("!HH", TYPE_WKS, CLASS_IN)  # TYPE, CLASS
        + struct.pack("!I", 3600)  # TTL
        + struct.pack("!H", len(wks))  # RDLENGTH
        + wks
    )

    # --- Answer 2: A ---
    a_rdata = bytes(int(o) for o in "192.0.2.1".split("."))
    a_answer = (
        encode_name(qname)
        + struct.pack("!HH", TYPE_A, CLASS_IN)  # TYPE, CLASS
        + struct.pack("!I", 3600)  # TTL
        + struct.pack("!H", len(a_rdata))  # RDLENGTH
        + a_rdata
    )

    return header + question + wks_answer + a_answer


def main():
    out_path = str(Path(__file__).with_suffix(""))

    dns_payload = build_dns_reply()

    # Server (53) -> client. This is the reply direction the DNS analyzer expects.
    pkt = (
        IP(src="192.0.2.53", dst="192.0.2.100")
        / UDP(sport=53, dport=54321)
        / Raw(load=dns_payload)
    )
    pkt.time = 0

    wrpcap(out_path, [pkt])
    print(f"Wrote {out_path} ({len(dns_payload)} bytes of DNS payload)")


if __name__ == "__main__":
    main()
