#!/usr/bin/env python3
"""One-line description of what packet/behavior this trace exercises.

A sentence or two on the mechanism being reproduced.

Generated with <original-tool>, adapted with <model-id> to use Scapy.
"""

from pathlib import Path

from scapy.all import IP, UDP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 40000
SERVER_PORT = 12345  # protocol port under test
BASE_TIME = 1_700_000_000.0


def pkt(is_orig, payload):
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, CLIENT_PORT, SERVER_PORT
        eth_src, eth_dst = "02:00:00:00:00:01", "02:00:00:00:00:02"
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, CLIENT_PORT
        eth_src, eth_dst = "02:00:00:00:00:02", "02:00:00:00:00:01"
    return (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / UDP(sport=sport, dport=dport)
        / Raw(payload)
    )


def build_packets():
    # UDP is connectionless: no handshake or teardown. Build the datagram(s)
    # directly. For a single-packet trace, just return one; drop pkt() entirely
    # if there is only ever one direction. Prefer an L7 Scapy layer over Raw
    # when one exists (e.g. DNS() from scapy.layers.dns).
    return [
        pkt(True, b"request payload under test"),
        pkt(False, b"response payload"),
    ]


def main():
    packets = build_packets()

    # Assign reproducible, monotonically increasing timestamps.
    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    # Plain, uncompressed pcap (nicer to inspect/diff). -> <name>.pcap
    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
