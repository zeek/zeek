#!/usr/bin/env python3
"""DNS/TCP SPF replies that exceed dns_max_spf_character_strings.

Two connections, each a complete DNS/TCP exchange (query and response):

  1. an SPF record with 1000 zero-length character strings, and
  2. an SPF record with 1000 one-byte character strings.

Both counts are well above the cap, so each connection should have its SPF
strings capped and be marked with an 'X'. The two variants confirm the cap
counts strings regardless of whether they are empty or not -- a run of empty
character strings is legal per RFC 1035 section 3.3.14, so parsing must not
reject it outright. SPF records (RFC 4408) use the same character-string
format as TXT.

Written with Claude Opus 4.8 using Scapy (AI assistance disclosed per AI_POLICY.md).
"""

from __future__ import annotations

import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, wrpcap
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
SERVER_PORT = 53
BASE_TIME = 1_700_000_000.0
SEGMENT_SIZE = 1400
QNAME = "example.com"
TYPE_SPF = 99  # RFC 4408: SPF resource record, same format as TXT

# Each connection is a full DNS/TCP exchange from a distinct client.
CONNECTIONS = [
    # (client_port, dns_id, character-string, repeat count)
    (40000, 0x1000, b"\x00", 1000),  # over cap: zero-length strings
    (40001, 0x2000, b"\x01A", 1000),  # over cap: one-byte strings ("A")
]


def pkt(client_port, is_orig, seq, ack, flags, payload=b""):
    """Build one Ethernet/IPv4/TCP packet for the given connection/direction."""
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, client_port, SERVER_PORT
        eth_src, eth_dst = "02:00:00:00:00:01", "02:00:00:00:00:02"
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, client_port
        eth_src, eth_dst = "02:00:00:00:00:02", "02:00:00:00:00:01"
    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    return p


def dns_frame(message: bytes) -> bytes:
    """Prefix a DNS message with its 2-byte length for TCP transport."""
    return struct.pack("!H", len(message)) + message


def spf_query(dns_id: int) -> bytes:
    """A conventional SPF query for QNAME."""
    return dns_frame(
        bytes(
            DNS(
                id=dns_id,
                rd=1,
                qr=0,
                qd=DNSQR(qname=QNAME, qtype=TYPE_SPF, qclass="IN"),
            )
        )
    )


def spf_reply(dns_id: int, character_string: bytes, count: int) -> bytes:
    """An SPF reply whose single record repeats character_string count times.

    Scapy's character-string field cannot emit a run of empty character strings
    (it drops empties and length-prefixes raw bytes), so the answer resource
    record is assembled by hand and carried as the DNS message's raw body.
    """
    rdata = character_string * count
    # owner=root(.), type=SPF(99), class=IN(1), ttl=60, then rdlen + rdata
    answer = b"\x00" + struct.pack("!HHIH", TYPE_SPF, 1, 60, len(rdata)) + rdata
    header = DNS(id=dns_id, qr=1, aa=0, rd=1, ra=1, qd=None, an=None, ancount=1)
    return dns_frame(bytes(header / Raw(answer)))


def build_connection(client_port, dns_id, character_string, count):
    """Build a complete DNS/TCP exchange: handshake, query, reply, teardown."""
    client_seq, server_seq = 1000, 2000
    packets = [
        pkt(client_port, True, client_seq, 0, "S"),
        pkt(client_port, False, server_seq, client_seq + 1, "SA"),
        pkt(client_port, True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    query = spf_query(dns_id)
    packets.append(pkt(client_port, True, client_seq, server_seq, "PA", query))
    client_seq += len(query)
    packets.append(pkt(client_port, False, server_seq, client_seq, "A"))

    reply = spf_reply(dns_id, character_string, count)
    for offset in range(0, len(reply), SEGMENT_SIZE):
        segment = reply[offset : offset + SEGMENT_SIZE]
        packets.append(pkt(client_port, False, server_seq, client_seq, "PA", segment))
        server_seq += len(segment)
    packets.append(pkt(client_port, True, client_seq, server_seq, "A"))

    # Clean FIN/ACK teardown (a FIN consumes one sequence number).
    packets.append(pkt(client_port, True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(client_port, False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(client_port, True, client_seq, server_seq, "A"))
    return packets


def main():
    packets = []
    for client_port, dns_id, character_string, count in CONNECTIONS:
        packets.extend(build_connection(client_port, dns_id, character_string, count))

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
