#!/usr/bin/env python3
"""Generate an HTTP PCAP with many unanswered pipelined requests.

The client sends minimal complete HTTP/0.9 requests while the server sends no
responses, so the requests accumulate unanswered.

Generated with OpenAI Codex, adapted with Claude Opus 4.8 to use Scapy and
gzip compress by default.
"""

import argparse
import gzip
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 40000
SERVER_PORT = 80
TCP_PAYLOAD_SIZE = 1400
REQUEST = b"GET /\r\n\r\n"
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


def build_packets(request_count):
    packets = [
        pkt(True, 1000, 0, "S"),
        pkt(False, 2000, 1001, "SA"),
        pkt(True, 1001, 2001, "A"),
    ]

    client_seq = 1001
    server_seq = 2001
    requests_per_packet = TCP_PAYLOAD_SIZE // len(REQUEST)
    remaining = request_count
    while remaining:
        count = min(remaining, requests_per_packet)
        payload = REQUEST * count
        packets.append(pkt(True, client_seq, server_seq, "PA", payload))
        client_seq += len(payload)
        remaining -= count

    return packets


def write_pcap(request_count):
    packets = build_packets(request_count)

    # Assign reproducible, monotonically increasing timestamps.
    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    with gzip.GzipFile(Path(__file__).with_suffix(".gz"), "wb", mtime=0) as f:
        wrpcap(f, packets)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=2000)
    args = parser.parse_args()
    if args.requests < 1:
        parser.error("--requests must be positive")
    write_pcap(args.requests)


if __name__ == "__main__":
    main()
