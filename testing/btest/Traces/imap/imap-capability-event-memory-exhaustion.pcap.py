#!/usr/bin/env python3
"""
Generate a queued IMAP capability-element burst PCAP.

The server answers a CAPABILITY command with a huge, MSS-sized response spread
over BLOCKS segments. The first segment is held back and only sent last, so the
whole response must be queued in the reassembler before the CAPABILITY event
fires with all elements at once.

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
SERVER_PORT = 143
BLOCK_SIZE = 1400
BLOCKS = 7489
HEADER = b"* CAPABILITY "
SUFFIX = b"\r\n"
BASE_TIME = 1_700_000_000.0


def pkt(is_orig, seq, ack, flags, payload=b""):
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, CLIENT_PORT, SERVER_PORT
        eth_src, eth_dst = "00:00:5e:00:53:01", "00:00:5e:00:53:02"
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, CLIENT_PORT
        eth_src, eth_dst = "00:00:5e:00:53:02", "00:00:5e:00:53:01"
    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    return p


def capability_block():
    body_size = BLOCK_SIZE - len(HEADER) - len(SUFFIX)
    return HEADER + b"A " * (body_size // 2) + b"A" * (body_size % 2) + SUFFIX


def generate(blocks):
    greeting = b"* OK ready\r\n"
    request = b"a CAPABILITY\r\n"
    server_seq = 2001 + len(greeting)
    client_seq = 1001 + len(request)
    response = capability_block()

    packets = [
        pkt(True, 1000, 0, "S"),
        pkt(False, 2000, 1001, "SA"),
        pkt(True, 1001, 2001, "A"),
        pkt(False, 2001, 1001, "PA", greeting),
        pkt(True, 1001, server_seq, "PA", request),
        pkt(False, server_seq, client_seq, "A"),
    ]

    # Send every segment except the first, then fill the withheld first segment
    # last so the response can only be delivered once the whole burst has been
    # queued in the reassembler.
    for index in range(1, blocks):
        packets.append(
            pkt(False, server_seq + index * BLOCK_SIZE, client_seq, "PA", response)
        )
    packets.append(pkt(False, server_seq, client_seq, "PA", response))

    # FIN/ACK teardown — client initiates close after receiving all data.
    final_server_seq = server_seq + blocks * BLOCK_SIZE
    packets.append(pkt(True, client_seq, final_server_seq, "A"))
    packets.append(pkt(True, client_seq, final_server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(False, final_server_seq, client_seq, "FA"))
    final_server_seq += 1
    packets.append(pkt(True, client_seq, final_server_seq, "A"))

    # Assign reproducible, monotonically increasing timestamps.
    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    path = Path(__file__).with_suffix(".gz")
    with gzip.GzipFile(path, "wb", mtime=0) as f:
        wrpcap(f, packets)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--blocks", type=int, default=BLOCKS)
    args = parser.parse_args()
    if args.blocks < 1:
        parser.error("--blocks must be positive")
    generate(args.blocks)


if __name__ == "__main__":
    main()
