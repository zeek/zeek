#!/usr/bin/env python3
"""Generate DNP3/TCP traffic with device attribute objects (group 0).

The trace has two TCP connections between a master (192.0.2.1, link
address 1) and an outstation (192.0.2.2:20000, link address 10), one frame
per TCP segment.

The first connection (port 40001) has, for each of the group 0 variations
196-210 and 244:

1. master: READ of g0vN, qualifier 0x00 (1-octet start and stop index), 0-0;
2. outstation: RESPONSE with g0vN, then g0v242 (software version, "1.2.3"),
   both with qualifier 0x00, 0-0.

The second connection (port 40002) has:

1. master: WRITE with g0v240 (maximum transmit fragment size), g0v245
   (user-assigned location), g0v246 (user-assigned ID code/number) and
   g0v247 (user-assigned device name), each with qualifier 0x00, 0-0.
   These are the user-writable device attributes (function codes 1 and 2)
   per DNP Users Group application note AN2013-004b, Table 3;
2. outstation: RESPONSE with no objects;
3. master: READ of g0v254 (all attributes), qualifier 0x06 (no range);
4. outstation: RESPONSE with g0v247.

Every attribute is a data type code, a length octet and that many octets of
value. Every frame is well formed, with valid header and block CRCs.

This script was written by Claude Code (Anthropic, model claude-opus-4-8).
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

READ = 0x01
WRITE = 0x02

# Attribute data type codes.
VSTR = 0x01
UINT = 0x02
FLT = 0x04
OSTR = 0x05
TIME = 0x07

# One attribute value per variation that lacked a case arm: (data type code, value).
ATTRIBUTES = {
    196: (VSTR, b"cfg-0042"),  # configuration ID
    197: (VSTR, b"7.3"),  # configuration version
    198: (TIME, struct.pack("<Q", 1_700_000_000_000)[:6]),  # configuration build date
    199: (
        TIME,
        struct.pack("<Q", 1_700_000_500_000)[:6],
    ),  # configuration last change date
    200: (OSTR, bytes.fromhex("0badc0de")),  # configuration signature
    201: (VSTR, b"SHA-256"),  # configuration signature algorithm
    202: (OSTR, bytes.fromhex("00112233445566778899aabbccddeeff")),  # mRID
    203: (FLT, struct.pack("<f", 12.5)),  # device altitude
    204: (FLT, struct.pack("<f", -0.25)),  # device longitude
    205: (FLT, struct.pack("<f", 51.5)),  # device latitude
    206: (VSTR, b"ops-b"),  # user-assigned secondary operator name
    207: (VSTR, b"ops-a"),  # user-assigned primary operator name
    208: (VSTR, b"feeder-7"),  # user-assigned system name
    209: (UINT, bytes([0x05])),  # secure authentication version
    210: (UINT, bytes([0x10])),  # number of security statistics per association
    244: (VSTR, b"example-utility"),  # user-assigned owner name
}

SW_VERSION = (VSTR, b"1.2.3")  # g0v242
DEVICE_NAME = (VSTR, b"rtu-12")  # g0v247

# The user-writable device attributes (function codes 1 and 2) per DNP Users
# Group application note AN2013-004b, Table 3. The WRITE connection carries
# these; g0v206, g0v207, g0v208 and g0v244 are read-only (function code 1).
WRITABLE = {
    240: (UINT, struct.pack("<H", 2048)),  # maximum transmit fragment size
    245: (VSTR, b"bay-04"),  # user-assigned location
    246: (VSTR, b"id-4021"),  # user-assigned ID code/number
    247: DEVICE_NAME,  # user-assigned device name
}


def g0_header(variation: int) -> bytes:
    """g0vN, qualifier 0x00 (1-octet start and stop index), range 0-0."""
    return bytes([0x00, variation, 0x00, 0x00, 0x00])


def g0_object(variation: int, attribute: tuple[int, bytes]) -> bytes:
    """g0vN header followed by one attribute: data type code, length, value."""
    data_type, value = attribute
    return g0_header(variation) + bytes([data_type, len(value)]) + value


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


def request(seq: int, function_code: int, objects: bytes) -> bytes:
    """A master request in one fragment: transport FIR|FIN, application FIR|FIN."""
    app = bytes([0xC0 | (seq & 0x0F), function_code]) + objects
    return link_frame(
        CTRL_MASTER_DATA,
        OUTSTATION_ADDR,
        MASTER_ADDR,
        bytes([0xC0 | (seq & 0x3F)]) + app,
    )


def response(seq: int, objects: bytes = b"") -> bytes:
    """An outstation RESPONSE in one fragment, IIN 0."""
    app = bytes([0xC0 | (seq & 0x0F), 0x81, 0x00, 0x00]) + objects
    return link_frame(
        CTRL_OUTSTATION_DATA,
        MASTER_ADDR,
        OUTSTATION_ADDR,
        bytes([0xC0 | (seq & 0x3F)]) + app,
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
    reads = []
    for seq, variation in enumerate(sorted(ATTRIBUTES)):
        reads.append((True, request(seq, READ, g0_header(variation))))
        reads.append(
            (
                False,
                response(
                    seq,
                    g0_object(variation, ATTRIBUTES[variation])
                    + g0_object(242, SW_VERSION),
                ),
            )
        )

    attributes = b"".join(
        g0_object(variation, WRITABLE[variation]) for variation in (240, 245, 246, 247)
    )
    writes = [
        (True, request(0, WRITE, attributes)),
        (False, response(0)),
        # g0v254, qualifier 0x06 (all objects, no range field).
        (True, request(1, READ, bytes([0x00, 0xFE, 0x06]))),
        (False, response(1, g0_object(247, DEVICE_NAME))),
    ]

    return session(40_001, reads, 1_700_000_000) + session(
        40_002, writes, 1_700_000_100
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
