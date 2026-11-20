#!/usr/bin/env python3
"""Three truncated TCP data segments for the content-extraction OOB read.

Each segment captures a single payload byte (A, B, C) while its IPv4 total
length and pcap wire length declare far more, each by a different amount.
TCP sequence numbers advance by the declared payload length, leaving holes
between the segments. With caplen < wirelen, set_contents_file() extraction
must write only the captured bytes rather than the declared length.

Adapted from an earlier reproducer with Claude Opus 5.5 to use Scapy.
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 31337
SERVER_PORT = 40000
BASE_TIME = 1_700_000_000.0

ETHERNET_LEN = 14
IP_TCP_HEADER_LEN = 40

# (captured payload, declared IPv4 total length). The last segment declares
# more than a page so that the over-read leaves the capture buffer; being last,
# it does not add a hole to the extracted contents.
SEGMENTS = [(b"A", 1_400), (b"B", 1_300), (b"C", 5_000)]


def pkt(flags, seq, payload=b"", ip_len=None):
    p = (
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
        / IP(src=CLIENT, dst=SERVER, len=ip_len)
        / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, seq=seq, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    return p


def build_packets():
    seq = 1000
    packets = [pkt("S", seq)]
    seq += 1

    for payload, ip_len in SEGMENTS:
        p = pkt("PA", seq, payload, ip_len)
        p.wirelen = ETHERNET_LEN + ip_len  # caplen stays at the captured bytes
        packets.append(p)
        seq += ip_len - IP_TCP_HEADER_LEN  # hole for the uncaptured payload

    return packets


def main():
    packets = build_packets()

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
