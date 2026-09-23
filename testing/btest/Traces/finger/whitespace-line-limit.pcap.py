#!/usr/bin/env python3
"""
Create a pcap with Finger requests whose whitespace exceeds the line limit.

The trace contains one request with overlong leading whitespace and one request
with overlong whitespace after /W. Generated with OpenAI Codex (GPT-5).
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

BASE_TIME = 1_700_000_000.0
CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
SERVER_PORT = 79
OVERLONG_WHITESPACE = 1_100


def pkt(orig, seq, ack, flags, payload=b"", client_port=40079):
    if orig:
        src_ip, dst_ip = CLIENT_IP, SERVER_IP
        src_mac, dst_mac = CLIENT_MAC, SERVER_MAC
        src_port, dst_port = client_port, SERVER_PORT
    else:
        src_ip, dst_ip = SERVER_IP, CLIENT_IP
        src_mac, dst_mac = SERVER_MAC, CLIENT_MAC
        src_port, dst_port = SERVER_PORT, client_port

    packet = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip, id=0x1234, flags="DF", ttl=64)
        / TCP(
            sport=src_port, dport=dst_port, seq=seq, ack=ack, flags=flags, window=64240
        )
    )

    if payload:
        packet /= Raw(payload)

    return packet


def flow(client_port, payload):
    client_seq = 1000
    server_seq = 8000

    packets = [
        pkt(True, client_seq, 0, "S", client_port=client_port),
        pkt(False, server_seq, client_seq + 1, "SA", client_port=client_port),
        pkt(True, client_seq + 1, server_seq + 1, "A", client_port=client_port),
    ]
    client_seq += 1
    server_seq += 1

    packets.append(
        pkt(True, client_seq, server_seq, "PA", payload, client_port=client_port)
    )
    client_seq += len(payload)

    packets.append(pkt(True, client_seq, server_seq, "FA", client_port=client_port))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA", client_port=client_port))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A", client_port=client_port))

    return packets


def stamp(packets):
    for index, packet in enumerate(packets):
        packet.time = BASE_TIME + index * 0.001

    return packets


leading_whitespace = b" " * OVERLONG_WHITESPACE + b"user\r\n"
post_whois_whitespace = b"/W" + b" " * OVERLONG_WHITESPACE + b"user\r\n"
packets = flow(40079, leading_whitespace) + flow(40080, post_whois_whitespace)

wrpcap(str(Path(__file__).with_suffix("")), stamp(packets))
