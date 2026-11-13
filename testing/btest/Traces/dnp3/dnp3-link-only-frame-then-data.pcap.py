#!/usr/bin/env python3
"""Generate DNP3/TCP traffic where a link-layer-only frame precedes other frames.

A DNP3 link frame with LENGTH 5 has no transport or application data; it is
10 octets long (REQUEST_LINK_STATUS and LINK_STATUS are typical, and stacks
send them as keep-alives). The trace has five TCP connections between a
master (192.0.2.1, link address 1) and an outstation (192.0.2.2:20000, link
address 10). Every frame is well formed, with valid header and block CRCs:

1. master: REQUEST_LINK_STATUS in one segment, then DIRECT_OPERATE (CROB
   LATCH_ON, index 0) in the next segment; outstation: RESPONSE echoing it.
2. Same as 1, but REQUEST_LINK_STATUS and DIRECT_OPERATE in one segment.
3. master: READ (class 0) and outstation: RESPONSE; then master:
   REQUEST_LINK_STATUS and DIRECT_OPERATE in one segment; outstation:
   RESPONSE echoing it.
4. master: DIRECT_OPERATE; outstation: LINK_STATUS and the RESPONSE echoing
   the DIRECT_OPERATE in one segment.
5. master: DIRECT_OPERATE; outstation: the RESPONSE echoing it, split into
   two transport segments (FIR, then FIN) with a LINK_STATUS between them,
   all in one TCP segment.

All application requests and responses should appear in dnp3.log.

Generated with the assistance of Claude (Anthropic, model claude-opus-5-5).
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, wrpcap

MASTER_IP = "192.0.2.1"
OUTSTATION_IP = "192.0.2.2"
DNP3_PORT = 20_000
MASTER_ADDR = 1
OUTSTATION_ADDR = 10

# Link-layer control octets: DIR (0x80), PRM (0x40), function code.
CTRL_REQUEST_LINK_STATUS = 0xC9  # master -> outstation, primary, FC 9
CTRL_LINK_STATUS = 0x0B  # outstation -> master, secondary, FC 11
CTRL_MASTER_DATA = 0xC4  # master -> outstation, primary, UNCONFIRMED_USER_DATA
CTRL_OUTSTATION_DATA = 0x44  # outstation -> master, primary, UNCONFIRMED_USER_DATA

# LATCH_ON, count 1, on-time 0, off-time 0, status 0.
CROB = bytes([0x03, 0x01]) + struct.pack("<II", 0, 0) + bytes([0x00])
# g12v1, qualifier 0x17 (1-octet count, 1-octet index), 1 item, index 0.
CROB_HEADER = bytes([0x0C, 0x01, 0x17, 0x01, 0x00])
READ_CLASS0 = bytes([0x01, 0x3C, 0x01, 0x06])  # READ, g60v1, all objects
DIRECT_OPERATE = bytes([0x05]) + CROB_HEADER + CROB


def dnp3_crc(data: bytes) -> bytes:
    """Return the 2-byte little-endian DNP3 CRC for a block of bytes."""
    crc = 0
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return struct.pack("<H", (~crc) & 0xFFFF)


def link_frame(control: int, dest: int, src: int, user_data: bytes = b"") -> bytes:
    """Build one DNP3 link frame, with a CRC after the header and every block."""
    header = bytes([0x05, 0x64, 5 + len(user_data), control]) + struct.pack(
        "<HH", dest, src
    )
    out = bytearray(header + dnp3_crc(header))
    for offset in range(0, len(user_data), 16):
        block = user_data[offset : offset + 16]
        out += block + dnp3_crc(block)
    return bytes(out)


def request(seq: int, app: bytes) -> bytes:
    """A master request in one fragment: transport FIR|FIN, application FIR|FIN."""
    return link_frame(
        CTRL_MASTER_DATA,
        OUTSTATION_ADDR,
        MASTER_ADDR,
        bytes([0xC0 | seq, 0xC0 | seq]) + app,
    )


def response(seq: int, objects: bytes = b"") -> bytes:
    """An outstation RESPONSE in one fragment, IIN 0."""
    app = bytes([0xC0 | seq, 0x81, 0x00, 0x00]) + objects
    return link_frame(
        CTRL_OUTSTATION_DATA, MASTER_ADDR, OUTSTATION_ADDR, bytes([0xC0 | seq]) + app
    )


def response_in_two_frames(seq: int, objects: bytes) -> tuple[bytes, bytes]:
    """An outstation RESPONSE whose fragment is split over two link frames (transport FIR, then FIN)."""
    app = bytes([0xC0 | seq, 0x81, 0x00, 0x00]) + objects
    half = len(app) // 2
    first = link_frame(
        CTRL_OUTSTATION_DATA,
        MASTER_ADDR,
        OUTSTATION_ADDR,
        bytes([0x40 | 0]) + app[:half],
    )
    last = link_frame(
        CTRL_OUTSTATION_DATA,
        MASTER_ADDR,
        OUTSTATION_ADDR,
        bytes([0x80 | 1]) + app[half:],
    )
    return first, last


REQUEST_LINK_STATUS = link_frame(CTRL_REQUEST_LINK_STATUS, OUTSTATION_ADDR, MASTER_ADDR)
LINK_STATUS = link_frame(CTRL_LINK_STATUS, MASTER_ADDR, OUTSTATION_ADDR)


def session(sport: int, segments: list[tuple[bool, bytes]], start: float) -> list:
    """A TCP connection carrying segments, each (from_master, payload), with ACKs and teardown."""
    to_out = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(
        src=MASTER_IP, dst=OUTSTATION_IP
    )
    to_master = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01") / IP(
        src=OUTSTATION_IP, dst=MASTER_IP
    )
    mseq, oseq = 1000, 5000

    pkts = [
        to_out / TCP(sport=sport, dport=DNP3_PORT, flags="S", seq=mseq),
        to_master
        / TCP(sport=DNP3_PORT, dport=sport, flags="SA", seq=oseq, ack=mseq + 1),
    ]
    mseq, oseq = mseq + 1, oseq + 1
    pkts.append(
        to_out / TCP(sport=sport, dport=DNP3_PORT, flags="A", seq=mseq, ack=oseq)
    )

    for from_master, payload in segments:
        if from_master:
            pkts.append(
                to_out
                / TCP(sport=sport, dport=DNP3_PORT, flags="PA", seq=mseq, ack=oseq)
                / payload
            )
            mseq += len(payload)
            pkts.append(
                to_master
                / TCP(sport=DNP3_PORT, dport=sport, flags="A", seq=oseq, ack=mseq)
            )
        else:
            pkts.append(
                to_master
                / TCP(sport=DNP3_PORT, dport=sport, flags="PA", seq=oseq, ack=mseq)
                / payload
            )
            oseq += len(payload)
            pkts.append(
                to_out
                / TCP(sport=sport, dport=DNP3_PORT, flags="A", seq=mseq, ack=oseq)
            )

    pkts.append(
        to_out / TCP(sport=sport, dport=DNP3_PORT, flags="FA", seq=mseq, ack=oseq)
    )
    pkts.append(
        to_master
        / TCP(sport=DNP3_PORT, dport=sport, flags="FA", seq=oseq, ack=mseq + 1)
    )
    pkts.append(
        to_out
        / TCP(sport=sport, dport=DNP3_PORT, flags="A", seq=mseq + 1, ack=oseq + 1)
    )

    for i, pkt in enumerate(pkts):
        pkt.time = start + i * 0.01
    return pkts


def build_packets() -> list:
    operate_response = CROB_HEADER + CROB
    split_response = response_in_two_frames(0, operate_response)
    return (
        session(
            40_001,
            [
                (True, REQUEST_LINK_STATUS),
                (True, request(0, DIRECT_OPERATE)),
                (False, response(0, operate_response)),
            ],
            1_700_000_000,
        )
        + session(
            40_002,
            [
                (True, REQUEST_LINK_STATUS + request(0, DIRECT_OPERATE)),
                (False, response(0, operate_response)),
            ],
            1_700_000_010,
        )
        + session(
            40_003,
            [
                (True, request(0, READ_CLASS0)),
                (False, response(0)),
                (True, REQUEST_LINK_STATUS + request(1, DIRECT_OPERATE)),
                (False, response(1, operate_response)),
            ],
            1_700_000_020,
        )
        + session(
            40_004,
            [
                (True, request(0, DIRECT_OPERATE)),
                (False, LINK_STATUS + response(0, operate_response)),
            ],
            1_700_000_030,
        )
        + session(
            40_005,
            [
                (True, request(0, DIRECT_OPERATE)),
                (False, split_response[0] + LINK_STATUS + split_response[1]),
            ],
            1_700_000_040,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "output", nargs="?", type=Path, default=Path(__file__).with_suffix("")
    )
    args = parser.parse_args()
    wrpcap(str(args.output), build_packets())


if __name__ == "__main__":
    main()
