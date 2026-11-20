#!/usr/bin/env python3
"""Create a TLS ServerHello whose extensions exceed their declared length.

The ServerHello declares a single 4-byte extension but carries additional empty
unknown extensions after the declared vector. Generated with OpenAI Codex
(GPT-5).
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

BASE_TIME = 1_700_000_000.0
CLIENT_IP = "192.0.2.1"
SERVER_IP = "192.0.2.2"
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_PORT = 40000
SERVER_PORT = 443
EXTENSION_COUNT = 64
DECLARED_EXTENSIONS_LENGTH = 4


def pkt(orig, seq, ack, flags, payload=b""):
    if orig:
        src_ip, dst_ip = CLIENT_IP, SERVER_IP
        src_mac, dst_mac = CLIENT_MAC, SERVER_MAC
        src_port, dst_port = CLIENT_PORT, SERVER_PORT
    else:
        src_ip, dst_ip = SERVER_IP, CLIENT_IP
        src_mac, dst_mac = SERVER_MAC, CLIENT_MAC
        src_port, dst_port = SERVER_PORT, CLIENT_PORT

    packet = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip, id=0x1234, flags="DF", ttl=64)
        / TCP(
            sport=src_port,
            dport=dst_port,
            seq=seq,
            ack=ack,
            flags=flags,
            window=64240,
        )
    )

    if payload:
        packet /= Raw(payload)

    return packet


def handshake(message_type, body):
    return bytes([message_type]) + len(body).to_bytes(3, "big") + body


def tls_record(payload):
    return b"\x16\x03\x03" + len(payload).to_bytes(2, "big") + payload


def server_hello():
    extensions = b"\xff\xff\x00\x00" * EXTENSION_COUNT

    body = b""
    body += b"\x03\x03"  # legacy_version: TLS 1.2
    body += bytes(range(32))  # random
    body += b"\x00"  # empty legacy_session_id
    body += b"\xc0\x2f"  # cipher suite
    body += b"\x00"  # null compression
    body += DECLARED_EXTENSIONS_LENGTH.to_bytes(2, "big")
    body += extensions

    return tls_record(handshake(2, body))


def main():
    client_seq = 1000
    server_seq = 8000
    payload = server_hello()

    packets = [
        pkt(True, client_seq, 0, "S"),
        pkt(False, server_seq, client_seq + 1, "SA"),
        pkt(True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    packets.append(pkt(False, server_seq, client_seq, "PA", payload))
    server_seq += len(payload)
    packets.append(pkt(True, client_seq, server_seq, "A"))

    packets.append(pkt(True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))

    for index, packet in enumerate(packets):
        packet.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
