#!/usr/bin/env python3
"""Generate IPv6 fragments that retain completed Zeek reassembly state."""

from pathlib import Path

from scapy.all import (
    Ether,
    IPv6,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    Raw,
    wrpcap,
)

FLOWS = 2
PAYLOAD_SIZE = 65_528
FRAGMENT_CHUNK_SIZE = 1_440
BASE_TIME = 1.0


def fragment_set(identifier: int) -> list:
    """Build one fragment set that can wrap the reassembled payload length."""
    payload = bytes([identifier & 0xFF]) * PAYLOAD_SIZE
    chunks = [
        payload[index : index + FRAGMENT_CHUNK_SIZE]
        for index in range(0, len(payload), FRAGMENT_CHUNK_SIZE)
    ]
    packets = []
    offset = 0
    for index, chunk in enumerate(chunks):
        more_fragments = index + 1 < len(chunks)
        packets.append(
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IPv6(src="2001:db8::1", dst="2001:db8::2", nh=0)
            / IPv6ExtHdrHopByHop(nh=44)
            / IPv6ExtHdrFragment(
                nh=17, offset=offset // 8, m=int(more_fragments), id=identifier
            )
            / Raw(load=chunk)
        )
        offset += len(chunk)
    return packets


def main() -> None:
    packets = []
    for flow in range(FLOWS):
        packets += fragment_set(0xA0000000 + flow)

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
