#!/usr/bin/env python3
"""Generate an SSLv2 connection with repeated ServerHello messages.

The trace contains a single TCP connection. The client sends one SSLv2
ClientHello; the server then sends ten SSLv2 ServerHello messages, each in its
own TCP segment and each carrying the same self-signed X.509 certificate. This
is not protocol conformant, but exercises how many certificates Zeek accepts
via the SSLv2 path on one connection.

Generated with Claude Code (Claude Opus 5.5), adapted with OpenAI GPT-5 Codex
to use as a Zeek BTest trace.
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

BASE_TIME = 1_700_000_000.0
CLIENT_MAC = "aa:bb:cc:00:00:01"
SERVER_MAC = "aa:bb:cc:00:00:02"
CLIENT_IP = "192.0.2.1"
CLIENT_PORT = 40001
SERVER_IP = "192.0.2.2"
SERVER_PORT = 443
NUM_SERVER_HELLOS = 10
SSL2_VERSION = 0x0002
SSL2_CIPHER = b"\x01\x00\x80"  # SSL_CK_RC4_128_WITH_MD5
DER_CERT = bytes.fromhex(
    "308201813082012ba00302010202141f8d1308628744d37c8c481ca8cf2449e6a806ab300d06092a864886f70d01010b050030153113301106035504030c0a6c"
    "696d69742e74657374301e170d3236313030373134353035345a170d3237313030373134353035345a30153113301106035504030c0a6c696d69742e74657374"
    "305c300d06092a864886f70d0101010500034b003048024100a4fe30f00e8dcff2dfe88230b54bc9c77d27b0230e73849dc81b82830348ddec781364e0ef6ec4"
    "3b463e960ba94a81e381023fc8e0328ef0ed74eebe8aed9a850203010001a3533051301d0e04160414eed8daa9972b76a08488114de383ef01696659"
    "82301f0603551d23041830168014eed8daa9972b76a08488114de383ef0169665982300f0603551d130101ff040530030101ff300d06092a864886f70d01010b"
    "05000341005412fd8e0bbb9e126dc7ada0d1fd5bc52345ea6cd5573bf9bc223f8eae069229bf7b4fb79305d8047aad40e78779bf87e8c4b0a4b9a54b2eec1042"
    "8896730a13"
)


def u16(value):
    return value.to_bytes(2, "big")


def ssl2_record(body):
    # SSLv2 record: 2-byte header with the high bit set, 15-bit length.
    return u16(0x8000 | len(body)) + body


def client_hello():
    challenge = b"A" * 16
    body = b"\x01" + u16(SSL2_VERSION)
    body += u16(len(SSL2_CIPHER)) + u16(0) + u16(len(challenge))
    body += SSL2_CIPHER + challenge
    return ssl2_record(body)


def server_hello():
    connection_id = b"B" * 16
    body = b"\x04\x00\x01" + u16(SSL2_VERSION)
    body += u16(len(DER_CERT)) + u16(len(SSL2_CIPHER)) + u16(len(connection_id))
    body += DER_CERT + SSL2_CIPHER + connection_id
    return ssl2_record(body)


def pkt(is_orig, seq, ack, flags, payload=b""):
    if is_orig:
        src_mac, dst_mac = CLIENT_MAC, SERVER_MAC
        src_ip, dst_ip = CLIENT_IP, SERVER_IP
        sport, dport = CLIENT_PORT, SERVER_PORT
    else:
        src_mac, dst_mac = SERVER_MAC, CLIENT_MAC
        src_ip, dst_ip = SERVER_IP, CLIENT_IP
        sport, dport = SERVER_PORT, CLIENT_PORT

    packet = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst=dst_ip, ttl=64)
        / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=65535)
    )

    if payload:
        packet /= Raw(payload)

    return packet


def main():
    packets = []
    client_seq = 1000
    server_seq = 2000

    packets.append(pkt(True, client_seq, 0, "S"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "SA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))

    payload = client_hello()
    packets.append(pkt(True, client_seq, server_seq, "PA", payload))
    client_seq += len(payload)
    packets.append(pkt(False, server_seq, client_seq, "A"))

    for _ in range(NUM_SERVER_HELLOS):
        payload = server_hello()
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
