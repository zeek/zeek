#!/usr/bin/env python3
"""Generate DNP3/TCP traffic with packed double-bit binary inputs (group 3, variation 1).

g3v1 packs two bits per point, four points per octet, so a range of N points
takes ceil(N / 4) octets. The trace has two TCP connections between a master
(192.0.2.1, link address 1) and an outstation (192.0.2.2:20000, link address
10). Each connection carries, one frame per TCP segment:

1. master: READ, class 0 (g60v1);
2. outstation: RESPONSE with g3v1 for a range of points (qualifier 0x00),
   followed by binary inputs with flags (g1v2) for points 0-1;
3. master: DIRECT_OPERATE, CROB LATCH_ON on binary output 0;
4. outstation: RESPONSE echoing the CROB.

The g3v1 range is points 0-5 (two octets, the last one half used) in the
first connection and points 0-7 (two full octets) in the second. Every frame
is well formed, with valid header and block CRCs.

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

CTRL_MASTER_DATA = 0xC4  # master -> outstation, primary, UNCONFIRMED_USER_DATA
CTRL_OUTSTATION_DATA = 0x44  # outstation -> master, primary, UNCONFIRMED_USER_DATA

# LATCH_ON, count 1, on-time 0, off-time 0, status 0.
CROB = bytes([0x03, 0x01]) + struct.pack("<II", 0, 0) + bytes([0x00])
# g12v1, qualifier 0x17 (1-octet count, 1-octet index), 1 item, index 0.
CROB_HEADER = bytes([0x0C, 0x01, 0x17, 0x01, 0x00])
DIRECT_OPERATE = bytes([0x05]) + CROB_HEADER + CROB

READ_CLASS0 = bytes([0x01, 0x3C, 0x01, 0x06])  # READ, g60v1, all objects


def g3v1(stop: int) -> bytes:
    """g3v1 for points 0..stop (qualifier 0x00), every point DETERMINED_ON (binary 10)."""
    count = stop + 1
    values = bytearray((count + 3) // 4)
    for point in range(count):
        values[point // 4] |= 0b10 << (2 * (point % 4))
    return bytes([0x03, 0x01, 0x00, 0x00, stop]) + bytes(values)


# g1v2, qualifier 0x00, points 0-1, flags online with state 1.
G1V2_POINTS = bytes([0x01, 0x02, 0x00, 0x00, 0x01, 0x81, 0x81])


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
    pkts = []
    for i, stop in enumerate((5, 7)):
        segments = [
            (True, request(0, READ_CLASS0)),
            (False, response(0, g3v1(stop) + G1V2_POINTS)),
            (True, request(1, DIRECT_OPERATE)),
            (False, response(1, CROB_HEADER + CROB)),
        ]
        pkts += session(40_001 + i, segments, 1_700_000_000 + 10 * i)
    return pkts


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
