#!/usr/bin/env python3
"""Generate IPv6 fragments that retain completed Zeek reassembly state."""

import contextlib
import sys
from pathlib import Path

from scapy.all import (
    Ether,
    IPv6,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    PcapWriter,
    Raw,
)

FLOWS = 2
PAYLOAD_SIZE = 65_528
FRAGMENT_CHUNK_SIZE = 1_440
OUTPUT = Path(__file__).with_name("ipv6-reassembly-state-leak.pcap")


def write_fragment_set(
    writer: PcapWriter, identifier: int, timestamp: int
) -> tuple[int, int]:
    """Write one fragment set that can wrap the reassembled payload length."""
    payload = bytes([identifier & 0xFF]) * PAYLOAD_SIZE
    chunks = [
        payload[index : index + FRAGMENT_CHUNK_SIZE]
        for index in range(0, len(payload), FRAGMENT_CHUNK_SIZE)
    ]
    offset = 0
    for index, chunk in enumerate(chunks):
        more_fragments = index + 1 < len(chunks)
        pkt = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IPv6(src="2001:db8::1", dst="2001:db8::2", nh=0)
            / IPv6ExtHdrHopByHop(nh=44)
            / IPv6ExtHdrFragment(
                nh=17, offset=offset // 8, m=int(more_fragments), id=identifier
            )
            / Raw(load=chunk)
        )
        pkt.time = timestamp
        writer.write(pkt)
        timestamp += 1
        offset += len(chunk)
    return timestamp, len(chunks)


def main() -> None:
    """Generate the requested PCAP."""
    packet_count = 0
    timestamp = 1
    writer = PcapWriter(str(OUTPUT), linktype=1)
    with contextlib.closing(writer):
        for flow in range(FLOWS):
            timestamp, flow_packets = write_fragment_set(
                writer, 0xA0000000 + flow, timestamp
            )
            packet_count += flow_packets
    print(
        f"wrote {packet_count} packets for {FLOWS} flows to {OUTPUT}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
