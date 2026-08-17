#!/usr/bin/env python3
"""Generate a DNP3 PCAP that trips the binpac flow-buffer teardown assertion.

The DNP3 analyzer hand-drives binpac's internal FlowBuffer (via BufferData)
instead of the generated, exception-safe DNP3_Flow::NewData path. This PCAP
sends a single DNP3 response whose application layer is fragmented across many
link frames but whose final ("FIN") transport bit is never set, so the fragment
is never completed and the reassembly buffer only grows. Once the accumulated
application data would push the buffer past BinPAC::flowbuffer_capacity_max, the
append throws mid-copy and leaves the FlowBuffer with buffered bytes and live
original-data pointers. Nothing resets it, so at connection teardown FlowEOF
reaches ClearPreviousData() and the invariant buffer_n_ == 0 fails.

The payload bytes are inert filler; no DNP3 object is ever parsed. This
reproducer performs no network I/O.

The default trace is sized for a fast regression test run with
"redef BinPAC::flowbuffer_capacity_max = 4096;". To trigger against a stock
build, pass --app-bytes 9000000 to cross the 8 MiB capacity-doubling step.

Generated/modified with OpenAI Codex (GPT-5).
"""

from __future__ import annotations

import argparse
import struct
from collections.abc import Iterator
from pathlib import Path

from scapy.all import IP, TCP, Ether, wrpcap

CLIENT_IP = "192.0.2.1"
SERVER_IP = "192.0.2.2"
CLIENT_PORT = 40_000
SERVER_PORT = 20_000  # DNP3

# DNP3 link frame budget. The analyzer keeps a single frame under its 300-byte
# internal buffer, so the maximum link "length" field is 255. That yields 250
# user-data bytes: 1 transport byte plus 249 application bytes.
LINK_LENGTH = 255
USER_DATA_LEN = LINK_LENGTH - 5  # bytes after ctrl+dest+src (transport + app)
APP_BYTES_PER_FRAME = USER_DATA_LEN - 1  # application bytes buffered per frame
TCP_SEGMENT_TARGET = 1460  # pack multiple frames per TCP segment
DEFAULT_APP_BYTES = 4_097  # overflows a 4 KiB flowbuffer cap


def dnp3_crc(data: bytes) -> bytes:
    """Return the 2-byte little-endian DNP3 CRC for a block of bytes."""
    crc = 0
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return struct.pack("<H", (~crc) & 0xFFFF)


def dnp3_frame(app_chunk: bytes, transport: int) -> bytes:
    """Build one DNP3 link frame carrying app_chunk application bytes."""
    user_data = bytes([transport]) + app_chunk
    link_header = bytes([0x05, 0x64, 5 + len(user_data), 0x44])
    link_header += struct.pack("<HH", 1, 1024)  # dest, src addresses

    encoded = bytearray()
    for offset in range(0, len(user_data), 16):
        block = user_data[offset : offset + 16]
        encoded += block + dnp3_crc(block)

    return link_header + dnp3_crc(link_header) + bytes(encoded)


def dnp3_frames(app_bytes: int) -> Iterator[bytes]:
    """Yield fragmented DNP3 response frames totaling app_bytes.

    The first frame sets FIR (0x40); no frame ever sets FIN (0x80), so the
    application fragment is never completed and the flow buffer only grows.
    """
    remaining = app_bytes
    index = 0

    while remaining > 0:
        transport = index % 64
        if index == 0:
            transport |= 0x40  # FIR: initial chunk

        chunk_len = min(APP_BYTES_PER_FRAME, remaining)
        remaining -= chunk_len
        index += 1

        # Deliberately never set 0x80 (FIN): the fragment stays incomplete.
        yield dnp3_frame(bytes(chunk_len), transport)


def dnp3_segments(app_bytes: int) -> Iterator[bytes]:
    """Pack the DNP3 frames into TCP-sized payloads."""
    segment = bytearray()

    for frame in dnp3_frames(app_bytes):
        if segment and len(segment) + len(frame) > TCP_SEGMENT_TARGET:
            yield bytes(segment)
            segment.clear()

        segment += frame

    if segment:
        yield bytes(segment)


def build_packets(app_bytes: int) -> list:
    """Return a TCP handshake followed by the fragmented DNP3 response."""
    eth = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
    client_isn = 1000
    server_isn = 2000

    pkts = [
        eth
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=client_isn),
        eth
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(
            sport=SERVER_PORT,
            dport=CLIENT_PORT,
            flags="SA",
            seq=server_isn,
            ack=client_isn + 1,
        ),
        eth
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(
            sport=CLIENT_PORT,
            dport=SERVER_PORT,
            flags="A",
            seq=client_isn + 1,
            ack=server_isn + 1,
        ),
    ]

    seq = server_isn + 1
    for payload in dnp3_segments(app_bytes):
        pkts.append(
            eth
            / IP(src=SERVER_IP, dst=CLIENT_IP)
            / TCP(
                sport=SERVER_PORT,
                dport=CLIENT_PORT,
                flags="PA",
                seq=seq,
                ack=client_isn + 1,
            )
            / payload
        )
        seq += len(payload)

    # Tear the connection down so the analyzer's Done() -> FlowEOF() runs,
    # which is where the poisoned flow buffer trips the assertion.
    pkts.append(
        eth
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(
            sport=SERVER_PORT,
            dport=CLIENT_PORT,
            flags="FA",
            seq=seq,
            ack=client_isn + 1,
        )
    )
    pkts.append(
        eth
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(
            sport=CLIENT_PORT,
            dport=SERVER_PORT,
            flags="FA",
            seq=client_isn + 1,
            ack=seq + 1,
        )
    )

    return pkts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output", nargs="?", type=Path, default=Path(__file__).with_suffix("")
    )
    parser.add_argument(
        "--app-bytes",
        type=int,
        default=DEFAULT_APP_BYTES,
        help="reassembled application bytes to force (default: 4,097, "
        "enough to overflow a 4 KiB BinPAC::flowbuffer_capacity_max; "
        "use 9,000,000 for a stock-cap reproducer)",
    )
    args = parser.parse_args()

    if args.app_bytes <= 0:
        parser.error("--app-bytes must be positive")

    pkts = build_packets(args.app_bytes)
    wrpcap(str(args.output), pkts)
    print(f"wrote {args.output} ({len(pkts)} packets, ~{args.app_bytes} app bytes)")


if __name__ == "__main__":
    main()
