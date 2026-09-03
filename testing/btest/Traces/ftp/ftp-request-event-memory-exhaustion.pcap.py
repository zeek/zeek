#!/usr/bin/env python3
"""Generate thousands of FTP requests in one reassembly delivery.

The capture sends all but the first request segment out of order, then closes
the gap so the whole contiguous run is delivered to the FTP analyzer in a single
reassembly pass. This reproducer performs no network I/O.

Generated originally by low-level struct wrangling, adapted by Claude Opus 4.8
to use Scapy and to gzip compress reproducibly.
"""

from __future__ import annotations

import argparse
import gzip
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 40_002
SERVER_PORT = 21
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
BASE_TIME = 1_700_000_000.0
SEGMENT_SIZE = 1_400


def pkt(server_to_client, seq, ack, flags, payload=b"", ts=0.0):
    """Build one checksummed Ethernet/IPv4/TCP packet (checksums via Scapy)."""
    if server_to_client:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, CLIENT_PORT
    else:
        src, dst, sport, dport = CLIENT, SERVER, CLIENT_PORT, SERVER_PORT

    p = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=65_535)
    )
    if payload:
        p = p / Raw(payload)
    p.time = BASE_TIME + ts
    return p


def build_packets(line_count: int) -> list:
    """Build one established FTP flow and its reordered request stream."""
    cseq = 1_000
    sseq = 2_000
    t = 0.0

    packets = [pkt(False, cseq, 0, "S", ts=t)]
    cseq += 1
    t += 1e-6
    packets.append(pkt(True, sseq, cseq, "SA", ts=t))
    sseq += 1
    t += 1e-6
    packets.append(pkt(False, cseq, sseq, "A", ts=t))

    priming_request = b"USER guest\r\n"
    t += 1e-6
    packets.append(pkt(False, cseq, sseq, "PA", priming_request, ts=t))
    cseq += len(priming_request)
    t += 1e-6
    packets.append(pkt(True, sseq, cseq, "A", ts=t))

    request = b"PWD\r\n" * line_count
    segments = [
        request[offset : offset + SEGMENT_SIZE]
        for offset in range(0, len(request), SEGMENT_SIZE)
    ]
    # Hold back segment 0 (the one adjacent to the primer) and send it last, so
    # the reassembler only closes the gap once every later segment is buffered.
    order = list(range(1, len(segments))) + [0]
    for index in order:
        t += 1e-6
        packets.append(
            pkt(False, cseq + index * SEGMENT_SIZE, sseq, "PA", segments[index], ts=t)
        )

    return packets


def write_pcap(path: Path, packets: list) -> None:
    """Write packets to a gzip-compressed Ethernet PCAP reproducibly."""
    with gzip.GzipFile(path, "wb", mtime=0) as output:
        wrpcap(output, packets)


def main() -> None:
    """Parse arguments and generate the capture."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output", nargs="?", type=Path, default=Path(__file__).with_suffix(".gz")
    )
    parser.add_argument("--lines", type=int, default=100_000)
    args = parser.parse_args()
    write_pcap(args.output, build_packets(args.lines))


if __name__ == "__main__":
    main()
