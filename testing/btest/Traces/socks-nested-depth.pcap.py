#!/usr/bin/env python3
"""Generate nested SOCKS handshakes for the analyzer depth-limit test.

Generated with OpenAI Codex; the accompanying PCAP is checked in for BTest.
"""

from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
CLIENT_MAC = "02:00:00:00:00:10"
SERVER_MAC = "02:00:00:00:00:20"


def tcp_frame(
    payload: bytes,
    *,
    sequence: int,
    acknowledgment: int,
    flags: str,
    originator: bool,
    identifier: int,
) -> Packet:
    """Build one Ethernet, IPv4, and TCP frame."""
    source_ip, destination_ip = (
        (CLIENT_IP, SERVER_IP) if originator else (SERVER_IP, CLIENT_IP)
    )
    source_mac, destination_mac = (
        (CLIENT_MAC, SERVER_MAC) if originator else (SERVER_MAC, CLIENT_MAC)
    )
    source_port, destination_port = (49152, 1080) if originator else (1080, 49152)
    frame = (
        Ether(src=source_mac, dst=destination_mac)
        / IP(src=source_ip, dst=destination_ip, id=identifier, flags="DF")
        / TCP(
            sport=source_port,
            dport=destination_port,
            seq=sequence,
            ack=acknowledgment,
            flags=flags,
            window=65535,
        )
    )
    if payload:
        frame /= Raw(load=payload)
    return frame


def main() -> None:
    """Write five nested SOCKS5 handshakes with deterministic timestamps."""
    packets = [
        tcp_frame(
            b"",
            sequence=1000,
            acknowledgment=0,
            flags="S",
            originator=True,
            identifier=1,
        ),
        tcp_frame(
            b"",
            sequence=5000,
            acknowledgment=1001,
            flags="SA",
            originator=False,
            identifier=2,
        ),
        tcp_frame(
            b"",
            sequence=1001,
            acknowledgment=5001,
            flags="A",
            originator=True,
            identifier=3,
        ),
    ]
    client_sequence = 1001
    server_sequence = 5001
    messages = (
        (True, b"\x05\x01\x00"),
        (False, b"\x05\x00"),
        (True, b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50"),
        (False, b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50"),
    )
    for _ in range(5):
        for originator, payload in messages:
            sequence = client_sequence if originator else server_sequence
            acknowledgment = server_sequence if originator else client_sequence
            packets.append(
                tcp_frame(
                    payload,
                    sequence=sequence,
                    acknowledgment=acknowledgment,
                    flags="PA",
                    originator=originator,
                    identifier=len(packets) + 1,
                )
            )
            if originator:
                client_sequence += len(payload)
            else:
                server_sequence += len(payload)
    packets.append(
        tcp_frame(
            b"",
            sequence=client_sequence,
            acknowledgment=server_sequence,
            flags="A",
            originator=True,
            identifier=len(packets) + 1,
        )
    )
    for index, packet in enumerate(packets):
        packet.time = 1 + index / 1000
    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
