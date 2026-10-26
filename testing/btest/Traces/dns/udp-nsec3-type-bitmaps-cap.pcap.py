#!/usr/bin/env python3
"""DNS/UDP NSEC3 replies with many type-bitmap window blocks.

Two query/response exchanges, each a single UDP request and reply, each reply
carrying one NSEC3 record (RFC 5155 section 3) whose Type Bit Maps field
repeats a window block 1000 times.

As with NSEC, the window number is a single octet, so a *valid* NSEC3 record
can contain at most 256 window blocks. Producing more -- the unbounded
type-bitmap growth this trace exercises -- requires repeating a window block,
which is well-formed framing but intentionally malformed window ordering. 1000
blocks is far above dns_max_nsec3_type_bitmaps (default 256), so each reply
should have its type bitmaps capped and the connection marked with an 'X'.

The two exchanges differ only in the repeated window's bitmap length (1 vs. 2
octets) to confirm the cap counts window blocks regardless of bitmap size. The
fixed NSEC3 fields (SHA-1 algorithm, no salt, a 20-octet next hashed owner
name) are otherwise conventional.

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
TYPE_NSEC3 = 50

# Each exchange is one DNS/UDP query and reply from a distinct client port.
EXCHANGES = [
    # (client_port, dns_id, bitmap, repeat count)
    (40000, 0x1000, b"\x01", 1000),  # over cap: 1-octet bitmaps
    (40001, 0x2000, b"\x01\x02", 1000),  # over cap: 2-octet bitmaps
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


def nsec3_query(dns_id: int) -> bytes:
    """A conventional NSEC3 query for QNAME."""
    return bytes(
        DNS(id=dns_id, rd=1, qr=0, qd=DNSQR(qname=QNAME, qtype=TYPE_NSEC3, qclass="IN"))
    )


def nsec3_reply(dns_id: int, bitmap: bytes, count: int) -> bytes:
    """An NSEC3 reply whose single record repeats one window block count times.

    Scapy's NSEC3 support does not emit arbitrary (here, intentionally repeated)
    window blocks, so the answer resource record is assembled by hand and
    carried as the DNS message's raw body.
    """
    # Type Bit Maps window block: window #0, bitmap length, bitmap octets.
    window_block = bytes([0, len(bitmap)]) + bitmap
    # Fixed NSEC3 fields (RFC 5155 section 3.2):
    #   hash alg = SHA-1 (1), flags = 0, iterations = 0,
    #   salt length = 0 (no salt), hash length = 20, next hashed owner name.
    fixed = struct.pack("!BBHB", 1, 0, 0, 0) + struct.pack("!B", 20) + b"\x11" * 20
    rdata = fixed + window_block * count
    # owner=root(.), type=NSEC3(50), class=IN(1), ttl=60, then rdlen + rdata
    answer = b"\x00" + struct.pack("!HHIH", TYPE_NSEC3, 1, 60, len(rdata)) + rdata
    header = DNS(id=dns_id, qr=1, aa=0, rd=1, ra=1, qd=None, an=None, ancount=1)
    return bytes(header / Raw(answer))


def build_exchange(client_port, dns_id, bitmap, count):
    """Build one DNS/UDP query and its oversized NSEC3 reply."""
    return [
        pkt(client_port, True, nsec3_query(dns_id)),
        pkt(client_port, False, nsec3_reply(dns_id, bitmap, count)),
    ]


def main():
    packets = []
    for client_port, dns_id, bitmap, count in EXCHANGES:
        packets.extend(build_exchange(client_port, dns_id, bitmap, count))

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
