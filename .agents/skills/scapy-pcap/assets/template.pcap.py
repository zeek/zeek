#!/usr/bin/env python3
"""One-line description of what flow/behavior this trace exercises.

A sentence or two on the mechanism being reproduced.

Generated with <original-tool>, adapted with <model-id> to use Scapy and gzip
compress by default.
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 40000
SERVER_PORT = 80  # protocol port under test
BASE_TIME = 1_700_000_000.0


def pkt(is_orig, seq, ack, flags, payload=b""):
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, CLIENT_PORT, SERVER_PORT
        eth_src, eth_dst = "02:00:00:00:00:01", "02:00:00:00:00:02"
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, CLIENT_PORT
        eth_src, eth_dst = "02:00:00:00:00:02", "02:00:00:00:00:01"
    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    return p


def build_packets():
    client_seq, server_seq = 1000, 2000
    packets = [
        pkt(True, client_seq, 0, "S"),
        pkt(False, server_seq, client_seq + 1, "SA"),
        pkt(True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    # ... append the flow's data packets here, advancing client_seq/server_seq
    # by len(payload) for each data segment ...

    # Clean FIN/ACK teardown, client-initiated (a FIN consumes one seq).
    packets.append(pkt(True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))
    return packets


def main():
    packets = build_packets()

    # Assign reproducible, monotonically increasing timestamps.
    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    # Plain, uncompressed pcap (nicer to inspect/diff). -> <name>.pcap
    wrpcap(str(Path(__file__).with_suffix("")), packets)

    # If the trace is highly compressible (large, repetitive), compress it
    # reproducibly instead and drop the plain write above:
    #   import gzip
    #   with gzip.GzipFile(Path(__file__).with_suffix(".gz"), "wb", mtime=0) as f:
    #       wrpcap(f, packets)


if __name__ == "__main__":
    main()
