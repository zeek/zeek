#!/usr/bin/env python3
"""Generate TLS handshakes that exceed Zeek's certificate-chain cap.

The trace contains three TLS 1.2 connections. One sends twelve certificates in
a single Certificate handshake message. Another sends two Certificate messages
with six certificates each, exercising that the cap is connection-wide across
messages. The third sends exactly ten certificates as a control.

Generated with OpenAI GPT-5 Codex to use Scapy.
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

BASE_TIME = 1_700_000_000.0
CLIENT_MAC = "aa:bb:cc:00:00:01"
SERVER_MAC = "aa:bb:cc:00:00:02"
SERVER_IP = "192.0.2.2"
SERVER_PORT = 443
TLS12 = b"\x03\x03"
DER_CERT = bytes.fromhex(
    "308201813082012ba00302010202141f8d1308628744d37c8c481ca8cf2449e6a806ab300d06092a864886f70d01010b050030153113301106035504030c0a6c"
    "696d69742e74657374301e170d3236313030373134353035345a170d3237313030373134353035345a30153113301106035504030c0a6c696d69742e74657374"
    "305c300d06092a864886f70d0101010500034b003048024100a4fe30f00e8dcff2dfe88230b54bc9c77d27b0230e73849dc81b82830348ddec781364e0ef6ec4"
    "3b463e960ba94a81e381023fc8e0328ef0ed74eebe8aed9a850203010001a3533051301d0603551d0e04160414eed8daa9972b76a08488114de383ef01696659"
    "82301f0603551d23041830168014eed8daa9972b76a08488114de383ef0169665982300f0603551d130101ff040530030101ff300d06092a864886f70d01010b"
    "05000341005412fd8e0bbb9e126dc7ada0d1fd5bc52345ea6cd5573bf9bc223f8eae069229bf7b4fb79305d8047aad40e78779bf87e8c4b0a4b9a54b2eec1042"
    "8896730a13"
)


def u16(value):
    return value.to_bytes(2, "big")


def u24(value):
    return value.to_bytes(3, "big")


def tls_record(payload):
    # TLS record: handshake content type, TLS 1.2 version, 16-bit length.
    return b"\x16" + TLS12 + u16(len(payload)) + payload


def handshake(message_type, body):
    # TLS handshake: 8-bit type, 24-bit body length, body.
    return tls_record(bytes([message_type]) + u24(len(body)) + body)


def client_hello():
    body = TLS12
    body += bytes(32)
    body += b"\x00"
    body += u16(2) + u16(0xC02F)
    body += b"\x01\x00"
    body += u16(0)
    return handshake(1, body)


def server_hello():
    body = TLS12
    body += bytes(32)
    body += b"\x00"
    body += u16(0xC02F)
    body += b"\x00"
    return handshake(2, body)


def certificate_message(count):
    entries = b"".join(u24(len(DER_CERT)) + DER_CERT for _ in range(count))
    return handshake(11, u24(len(entries)) + entries)


def pkt(is_orig, seq, ack, flags, client_ip, client_port, payload=b""):
    if is_orig:
        src_mac, dst_mac = CLIENT_MAC, SERVER_MAC
        src_ip, dst_ip = client_ip, SERVER_IP
        sport, dport = client_port, SERVER_PORT
    else:
        src_mac, dst_mac = SERVER_MAC, CLIENT_MAC
        src_ip, dst_ip = SERVER_IP, client_ip
        sport, dport = SERVER_PORT, client_port

    packet = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip, ttl=64)
        / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=65535)
    )

    if payload:
        packet /= Raw(payload)

    return packet


def add_connection(packets, client_ip, client_port, certificate_messages):
    client_seq = 1000
    server_seq = 2000

    packets.append(pkt(True, client_seq, server_seq, "S", client_ip, client_port))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "SA", client_ip, client_port))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A", client_ip, client_port))

    payload = client_hello()
    packets.append(
        pkt(True, client_seq, server_seq, "PA", client_ip, client_port, payload)
    )
    client_seq += len(payload)
    packets.append(pkt(False, server_seq, client_seq, "A", client_ip, client_port))

    for payload in [server_hello(), *certificate_messages]:
        packets.append(
            pkt(False, server_seq, client_seq, "PA", client_ip, client_port, payload)
        )
        server_seq += len(payload)
        packets.append(pkt(True, client_seq, server_seq, "A", client_ip, client_port))

    packets.append(pkt(True, client_seq, server_seq, "FA", client_ip, client_port))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA", client_ip, client_port))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A", client_ip, client_port))


def main():
    packets = []
    add_connection(packets, "192.0.2.1", 40001, [certificate_message(12)])
    add_connection(
        packets,
        "192.0.2.3",
        40003,
        [certificate_message(6), certificate_message(6)],
    )
    add_connection(packets, "192.0.2.4", 40004, [certificate_message(10)])

    for index, packet in enumerate(packets):
        packet.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
