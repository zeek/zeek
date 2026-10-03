#!/usr/bin/env python3
"""
Generate IPv6 Multicast Listener Discovery v2 (MLDv2) Report packets using
Scapy, as a raw-IPv6 pcap (no link layer) written beside this script.

The five packets exercise: a report with four multicast address records, an
empty report, a record claiming more sources than it carries, a record with
auxiliary data, and a record claiming auxiliary data it does not carry.

Generated with Claude Sonnet 4.6 (Anthropic), adapted with Claude Sonnet 5.5
(Anthropic) to use fixed addresses and timestamps so the trace is reproducible.
"""

from pathlib import Path

from scapy.all import (
    ICMPv6MLDMultAddrRec,
    ICMPv6MLReport2,
    IPv6,
    wrpcap,
)

BASE_TIME = 1_700_000_000.0

# Link-local source addresses, one per packet. The first two also serve as
# record sources. The btest baseline pins these values.
SRC1 = "fe80::f16d:891:6486"
SRC2 = "fe80::794d:737e:8532"
SRC3 = "fe80::63d:6a4a:6fb9"
SRC4 = "fe80::4e56:e0aa:955f"
SRC5 = "fe80::f1a2:d2d2:bd20"

# MLDv2 record types.
MODE_IS_INCLUDE = 1
MODE_IS_EXCLUDE = 2
CHANGE_TO_INCLUDE = 3
CHANGE_TO_EXCLUDE = 4


def report(src, records):
    # hlim is pinned to the value in the committed trace (Scapy would pick 255).
    return IPv6(src=src, dst="ff02::16", hlim=64) / ICMPv6MLReport2(records=records)


packets = [
    # Four well-formed records.
    report(
        SRC1,
        [
            ICMPv6MLDMultAddrRec(
                rtype=MODE_IS_INCLUDE, dst="ff02::480e:413c", sources=[SRC1, SRC2]
            ),
            ICMPv6MLDMultAddrRec(
                rtype=MODE_IS_EXCLUDE, dst="ff02::e785:33ce", sources=[SRC1]
            ),
            ICMPv6MLDMultAddrRec(
                rtype=CHANGE_TO_INCLUDE, dst="ff02::3c05:cd57", sources=[]
            ),
            ICMPv6MLDMultAddrRec(
                rtype=CHANGE_TO_EXCLUDE, dst="ff02::a8c9:5e9c", sources=[SRC2]
            ),
        ],
    ),
    # No multicast address records.
    report(SRC2, []),
    # Malformed: the record claims 3 sources but carries only 2.
    report(
        SRC3,
        [
            ICMPv6MLDMultAddrRec(
                rtype=MODE_IS_INCLUDE,
                dst="ff02::9b64:84e6",
                sources_number=3,
                sources=[SRC1, SRC2],
            )
        ],
    ),
    # One source and 8 bytes (2 words) of auxiliary data.
    report(
        SRC4,
        [
            ICMPv6MLDMultAddrRec(
                rtype=MODE_IS_EXCLUDE,
                dst="ff02::d4a4:fca",
                sources=[SRC1],
                auxdata_len=2,
                auxdata=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            )
        ],
    ),
    # Malformed: the record claims 2 words of auxiliary data but carries none.
    report(
        SRC5,
        [
            ICMPv6MLDMultAddrRec(
                rtype=MODE_IS_INCLUDE,
                dst="ff02::489a:eb6",
                sources=[SRC2],
                auxdata_len=2,
            )
        ],
    ),
]

for index, p in enumerate(packets):
    p.time = BASE_TIME + index * 0.001

wrpcap(str(Path(__file__).with_suffix("")), packets)
