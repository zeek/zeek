#!/usr/bin/env python3
"""Generate DNP3/TCP traffic with double-bit binary input events (group 4, variations 1-3).

The trace has three TCP connections between a master (192.0.2.1, link
address 1) and an outstation (192.0.2.2:20000, link address 10), one per
variation of group 4. Each connection carries, one frame per TCP segment:

1. master: READ, class 1 events (g60v2);
2. outstation: RESPONSE with one double-bit binary input event for point 7
   (qualifier 0x28), followed by one binary input event without time (g2v1)
   for point 3;
3. master: DIRECT_OPERATE, CROB LATCH_ON on binary output 0;
4. outstation: RESPONSE echoing the CROB.

The group 4 object sizes are those of the DNP3 object library: g4v1 is the
flags octet only, g4v2 adds a 48-bit absolute time, g4v3 a 16-bit relative
time. Every frame is well formed, with valid header and block CRCs.

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
READ_CLASS1 = bytes([0x01, 0x3C, 0x02, 0x06])  # READ, g60v2, all objects
DIRECT_OPERATE = bytes([0x05]) + CROB_HEADER + CROB

FLAGS = 0x81  # online, state DETERMINED_ON (double-bit value 2)
TIME48 = (1_700_000_000_000).to_bytes(6, "little")  # milliseconds since the epoch
TIME16 = struct.pack("<H", 0x0010)
# Object header: group 4, variation, qualifier 0x28 (2-octet count, 2-octet index prefix), 1 item, index 7.
G4_EVENTS = {
    1: bytes([0x04, 0x01, 0x28]) + struct.pack("<HH", 1, 7) + bytes([FLAGS]),
    2: bytes([0x04, 0x02, 0x28]) + struct.pack("<HH", 1, 7) + bytes([FLAGS]) + TIME48,
    3: bytes([0x04, 0x03, 0x28]) + struct.pack("<HH", 1, 7) + bytes([FLAGS]) + TIME16,
}
# g2v1, qualifier 0x28, 1 item, index 3, flags online and state 1.
G2V1_EVENT = bytes([0x02, 0x01, 0x28]) + struct.pack("<HH", 1, 3) + bytes([0x81])


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
    for i, variation in enumerate(sorted(G4_EVENTS)):
        segments = [
            (True, request(0, READ_CLASS1)),
            (False, response(0, G4_EVENTS[variation] + G2V1_EVENT)),
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
