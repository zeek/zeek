#!/usr/bin/env python3

"""Generate a PostgreSQL identified-field amplification PCAP.

The trace contains one TCP connection to port 5432. After the startup
handshake the server sends a single ErrorResponse ('E', default) or
NoticeResponse ('N', --notice) message whose body carries thousands of empty
identified fields. PostgreSQL's Spicy parser emits one event per two-byte
field and the default policy retains each formatted field until the response
ends, so a small on-the-wire message expands into large in-memory state.

This script was used to produce the following two PCAPs:

    postgresql-error-field-memory-exhaustion.pcap.gz (default invocation)
    postgresql-notice-field-memory-exhaustion.pcap.gz (using --notice)

The original reproducer was generated with OpenAI Codex as a hand-rolled PCAP
writer and performs no network I/O. It was adapted to Scapy by Opus 4.8 to
match the other .pcap.py generator scripts in this tree.
"""

from __future__ import annotations

import argparse
import gzip
import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_PORT = 40000
SERVER_PORT = 5432
CHUNK_SIZE = 1400
MAX_FIELDS = 10_000_000


def identified_response(field_count: int, notice: bool) -> bytes:
    """Build a response with many empty fields."""
    content = b"M\x00" * field_count + b"\x00"
    message_type = b"N" if notice else b"E"
    return message_type + struct.pack("!I", 4 + len(content)) + content


def build_packets(field_count: int, notice: bool):
    """Build a handshake, startup message, and segmented server response."""
    client_seq = 1000
    server_seq = 5000

    packets = [
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT, dst=SERVER)
        / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=client_seq),
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER, dst=CLIENT)
        / TCP(
            sport=SERVER_PORT,
            dport=CLIENT_PORT,
            flags="SA",
            seq=server_seq,
            ack=client_seq + 1,
        ),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT, dst=SERVER)
        / TCP(
            sport=CLIENT_PORT,
            dport=SERVER_PORT,
            flags="A",
            seq=client_seq + 1,
            ack=server_seq + 1,
        ),
    ]

    # StartupMessage: Int32 length, Int32 protocol version 3.0, then the
    # null-terminated "a"="b" parameter pair and the final terminator.
    startup = struct.pack("!II", 13, 0x00030000) + b"a\x00b\x00\x00"
    packets.append(
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT, dst=SERVER)
        / TCP(
            sport=CLIENT_PORT,
            dport=SERVER_PORT,
            flags="PA",
            seq=client_seq + 1,
            ack=server_seq + 1,
        )
        / startup
    )
    client_seq += 1 + len(startup)

    response = identified_response(field_count, notice)
    seq = server_seq + 1
    for offset in range(0, len(response), CHUNK_SIZE):
        chunk = response[offset : offset + CHUNK_SIZE]
        packets.append(
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src=SERVER, dst=CLIENT)
            / TCP(
                sport=SERVER_PORT,
                dport=CLIENT_PORT,
                flags="PA",
                seq=seq,
                ack=client_seq,
            )
            / chunk
        )
        seq += len(chunk)

    # Fixed timestamps keep wrpcap() output reproducible across runs.
    for i, packet in enumerate(packets):
        packet.time = 1_700_000_000.0 + i / 1000.0

    return packets, len(response)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o",
        "--output",
        default=Path(__file__).with_suffix(".gz"),
        type=Path,
        help="output pcap.gz path",
    )
    parser.add_argument(
        "-n",
        "--fields",
        type=int,
        default=100_000,
        help="number of identified fields in the response",
    )
    parser.add_argument(
        "--notice",
        action="store_true",
        help="emit a NoticeResponse ('N') instead of an ErrorResponse ('E')",
    )
    args = parser.parse_args()

    if not 1 <= args.fields <= MAX_FIELDS:
        parser.error(f"--fields must be between 1 and {MAX_FIELDS}")

    packets, response_len = build_packets(args.fields, args.notice)
    # wrpcap() supports gz=1, but that's not reproducible, so pass a GzipFile
    # instance with mtime=0 that makes the output reproducible.
    with gzip.GzipFile(args.output, "wb", mtime=0) as f:
        wrpcap(f, packets)
    print(
        f"wrote {args.output}: fields={args.fields} "
        f"response_bytes={response_len} packets={len(packets)}"
    )


if __name__ == "__main__":
    main()
