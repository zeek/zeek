#!/usr/bin/env python3
"""DNS/UDP TXT replies that exceed dns_max_txt_character_strings.

Two query/response exchanges, each a single UDP request and reply:

  1. a TXT record with 1000 zero-length character strings, and
  2. a TXT record with 1000 one-byte character strings.

Both counts are well above the cap, so each exchange should have its TXT
strings capped and be marked with an 'X'. The two variants confirm the cap
counts strings regardless of whether they are empty or not -- a run of empty
character strings is legal per RFC 1035 section 3.3.14, so parsing must not
reject it outright.

This is the UDP counterpart to tcp-txt-character-strings-cap.pcap.py.

Written with Claude Opus 4.8 using Scapy (AI assistance disclosed per AI_POLICY.md).
"""

from __future__ import annotations

import struct
from pathlib import Path

from scapy.all import IP, UDP, Ether, wrpcap
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
SERVER_PORT = 53
BASE_TIME = 1_700_000_000.0
QNAME = "example.com"

# Each exchange is one DNS/UDP query and reply from a distinct client port.
EXCHANGES = [
    # (client_port, dns_id, character-string, repeat count)
    (40000, 0x1000, b"\x00", 1000),  # over cap: zero-length strings
    (40001, 0x2000, b"\x01A", 1000),  # over cap: one-byte strings ("A")
]


def pkt(client_port, is_orig, payload):
    """Build one Ethernet/IPv4/UDP DNS packet for the given exchange/direction."""
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, client_port, SERVER_PORT
        eth_src, eth_dst = "02:00:00:00:00:01", "02:00:00:00:00:02"
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, client_port
        eth_src, eth_dst = "02:00:00:00:00:02", "02:00:00:00:00:01"
    return (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / UDP(sport=sport, dport=dport)
        / Raw(payload)
    )


def txt_query(dns_id: int) -> bytes:
    """A conventional TXT query for QNAME."""
    return bytes(
        DNS(id=dns_id, rd=1, qr=0, qd=DNSQR(qname=QNAME, qtype="TXT", qclass="IN"))
    )


def txt_reply(dns_id: int, character_string: bytes, count: int) -> bytes:
    """A TXT reply whose single record repeats character_string count times.

    Scapy's TXT field cannot emit a run of empty character strings (it drops
    empties and length-prefixes raw bytes), so the answer resource record is
    assembled by hand and carried as the DNS message's raw body.
    """
    rdata = character_string * count
    # owner=root(.), type=TXT(16), class=IN(1), ttl=60, then rdlen + rdata
    answer = b"\x00" + struct.pack("!HHIH", 16, 1, 60, len(rdata)) + rdata
    header = DNS(id=dns_id, qr=1, aa=0, rd=1, ra=1, qd=None, an=None, ancount=1)
    return bytes(header / Raw(answer))


def build_exchange(client_port, dns_id, character_string, count):
    """Build one DNS/UDP query and its oversized TXT reply."""
    return [
        pkt(client_port, True, txt_query(dns_id)),
        pkt(client_port, False, txt_reply(dns_id, character_string, count)),
    ]


def main():
    packets = []
    for client_port, dns_id, character_string, count in EXCHANGES:
        packets.extend(build_exchange(client_port, dns_id, character_string, count))

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
