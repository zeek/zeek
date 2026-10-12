#!/usr/bin/env python3
"""Generate a SOCKS5 exchange with IPv6 request and bound addresses for #5854.

Based on the reproducer supplied for Zeek issue #5854.
Adapted with ByteAsk (GPT-6) using Scapy's SOCKS layers, deterministic timestamps,
and a complete TCP handshake and teardown.
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap
from scapy.contrib.socks import SOCKS, SOCKS5Reply, SOCKS5Request

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 40001
SERVER_PORT = 1080
ADDRESS = "1111:2222:3333:4444:5555:6666:7777:8888"
BASE_TIME = 1_700_000_000.0


def pkt(is_orig, seq, ack, flags, payload=b""):
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, CLIENT_PORT, SERVER_PORT
        eth_src, eth_dst = "02:00:00:00:00:01", "02:00:00:00:00:02"
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, CLIENT_PORT
        eth_src, eth_dst = "02:00:00:00:00:02", "02:00:00:00:00:01"

    packet = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        packet /= Raw(payload)
    return packet


def build_packets():
    client_seq, server_seq = 1000, 2000
    packets = [
        pkt(True, client_seq, 0, "S"),
        pkt(False, server_seq, client_seq + 1, "SA"),
        pkt(True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    request = bytes(SOCKS() / SOCKS5Request(cd=1, atyp=4, addr=ADDRESS, port=80))
    reply = bytes(SOCKS() / SOCKS5Reply(rep=0, atyp=4, addr=ADDRESS, port=80))

    # Scapy's SOCKS layer does not implement authentication negotiation.
    # Offer version 5, one method, no authentication; accept that method.
    for is_orig, payload in (
        (True, b"\x05\x01\x00"),
        (False, b"\x05\x00"),
        (True, request),
        (False, reply),
    ):
        if is_orig:
            packets.append(pkt(True, client_seq, server_seq, "PA", payload))
            client_seq += len(payload)
        else:
            packets.append(pkt(False, server_seq, client_seq, "PA", payload))
            server_seq += len(payload)

    # Acknowledge the reply, then close both sides of the connection.
    packets.append(pkt(True, client_seq, server_seq, "A"))
    packets.append(pkt(True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))
    return packets


def main():
    packets = build_packets()
    for index, packet in enumerate(packets):
        packet.time = BASE_TIME + index * 0.001
    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
