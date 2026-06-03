#!/usr/bin/env python3
"""
Generate nflog-bad-tlv-len.pcap: a LINKTYPE_NFLOG packet whose first
non-payload TLV claims a length larger than the bytes left in the capture.
Walking that TLV used to underflow the remaining-length counter and read the
next TLV header out of bounds; the analyzer now flags nflog_bad_tlv_len.
"""

import struct
from pathlib import Path

LINKTYPE_NFLOG = 239

# byte 0: address family, byte 1: version, bytes 2-3: resource id
NFLOG_HEADER = struct.pack("<BBH", 2, 0, 0)

# TLV length and type are in host byte order. Type 1 is not the payload type
# (9), and length 0x0100 runs well past the four value bytes that follow.
BAD_TLV = struct.pack("<HH", 0x0100, 1) + b"\x00\x00\x00\x00"


def main():
    payload = NFLOG_HEADER + BAD_TLV

    global_header = struct.pack(
        "<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_NFLOG
    )
    record_header = struct.pack("<IIII", 0, 0, len(payload), len(payload))

    out = Path(__file__).resolve().parent / "nflog-bad-tlv-len.pcap"
    out.write_bytes(global_header + record_header + payload)
    print(f"Wrote 1 packet to {out}")


if __name__ == "__main__":
    main()
