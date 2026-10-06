#!/usr/bin/env python3
"""Generate SMTP DATA with one oversized first MIME header line.

Generated with OpenAI Codex (GPT-5).
"""

import gzip
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

BASE_TIME = 1_700_000_000.0
CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_PORT = 54321
SERVER_PORT = 25
CRLF = b"\r\n"
FILLER_SIZE = 256 * 1024
SEGMENT_SIZE = 1400


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
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )

    if payload:
        packet /= Raw(payload)

    return packet


def message():
    return (
        b"From: a@attacker.example"
        + CRLF
        + b"To: b@target.example"
        + CRLF
        + b"Subject: "
        + b"A" * FILLER_SIZE
        + CRLF
        + CRLF
        + b"poc body"
        + CRLF
        + b"."
        + CRLF
    )


def main():
    packets = []
    client_seq = 1000
    server_seq = 5000

    packets.append(pkt(True, client_seq, 0, "S"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "SA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))

    def send(is_orig, payload):
        nonlocal client_seq, server_seq

        for offset in range(0, len(payload), SEGMENT_SIZE):
            chunk = payload[offset : offset + SEGMENT_SIZE]

            if is_orig:
                packets.append(pkt(True, client_seq, server_seq, "PA", chunk))
                client_seq += len(chunk)
                packets.append(pkt(False, server_seq, client_seq, "A"))
            else:
                packets.append(pkt(False, server_seq, client_seq, "PA", chunk))
                server_seq += len(chunk)
                packets.append(pkt(True, client_seq, server_seq, "A"))

    send(False, b"220 target.example ESMTP ready" + CRLF)
    send(True, b"EHLO attacker.example" + CRLF)
    send(False, b"250 target.example" + CRLF)
    send(True, b"MAIL FROM:<a@attacker.example>" + CRLF)
    send(False, b"250 OK" + CRLF)
    send(True, b"RCPT TO:<b@target.example>" + CRLF)
    send(False, b"250 OK" + CRLF)
    send(True, b"DATA" + CRLF)
    send(False, b"354 End data with <CR><LF>.<CR><LF>" + CRLF)
    send(True, message())
    send(False, b"250 OK: queued" + CRLF)
    send(True, b"QUIT" + CRLF)
    send(False, b"221 Bye" + CRLF)

    packets.append(pkt(True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))

    for index, packet in enumerate(packets):
        packet.time = BASE_TIME + index * 0.001

    with gzip.GzipFile(Path(__file__).with_suffix(".gz"), "wb", mtime=0) as f:
        wrpcap(f, packets)


if __name__ == "__main__":
    main()
