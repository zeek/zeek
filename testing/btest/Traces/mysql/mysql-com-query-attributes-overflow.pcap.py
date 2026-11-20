#!/usr/bin/env python3
"""
Reproducer provided by Communications Security Establishment, CSE. Slightly
adapted to use eth link layer and adapt the output file.
"""

import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLI, SRV = "10.0.0.1", "10.0.0.2"
CLI_MAC, SRV_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02"
CPORT, SPORT = 40000, 3306


def mysql_pkt(seq, body):
    return struct.pack("<I", len(body))[:3] + bytes([seq]) + body


greeting_body = (
    b"\x0a"  # protocol version 10
    b"8.0.0\x00"  # server_version
    + struct.pack("<I", 1234)  # connection_id
    + b"ABCDEFGH"  # auth_plugin_data_part_1 (8)
    + b"\x00"  # filler
    + struct.pack("<H", 0x0200)  # capability_flag_1 (CLIENT_PROTOCOL_41)
    + b"\x21"  # character_set
    + struct.pack("<H", 0x0002)  # status_flags
    + struct.pack("<H", 0x0800)  # capability_flags_2: QUERY_ATTRIBUTES>>16
    + b"\x00"  # auth_plugin_data_len
    + b"\x00" * 10  # reserved
    + b"I" * 13  # auth_plugin_data_part_2
)
greeting = mysql_pkt(0, greeting_body)

login_body = (
    struct.pack("<I", 0x08000200)  # cap_flags: PROTOCOL_41 | QUERY_ATTRIBUTES
    + struct.pack("<I", 1 << 24)  # max_pkt_size
    + b"\x21"  # char_set
    + b"\x00" * 23  # pad
    + b"root\x00"  # username
    + b"\x00"  # password: LengthEncodedString len=0
)
login = mysql_pkt(1, login_body)
ok = mysql_pkt(2, b"\x00\x00\x00\x02\x00\x00\x00")  # server OK -> COMMAND_PHASE
# COM_QUERY | LEI 0xfe count=0x7FFFFFFF | set_count LEI 0
query = mysql_pkt(0, b"\x03" + b"\xfe" + struct.pack("<Q", 0x7FFFFFFF) + b"\x00")

pkts = []
cseq, sseq = 1000, 2000
pkts.append(
    Ether(src=CLI_MAC, dst=SRV_MAC)
    / IP(src=CLI, dst=SRV)
    / TCP(sport=CPORT, dport=SPORT, flags="S", seq=cseq)
)
pkts.append(
    Ether(src=SRV_MAC, dst=CLI_MAC)
    / IP(src=SRV, dst=CLI)
    / TCP(sport=SPORT, dport=CPORT, flags="SA", seq=sseq, ack=cseq + 1)
)
cseq += 1
sseq += 1
pkts.append(
    Ether(src=CLI_MAC, dst=SRV_MAC)
    / IP(src=CLI, dst=SRV)
    / TCP(sport=CPORT, dport=SPORT, flags="A", seq=cseq, ack=sseq)
)


def send(data, orig):
    global cseq, sseq
    if orig:
        pkts.append(
            Ether(src=CLI_MAC, dst=SRV_MAC)
            / IP(src=CLI, dst=SRV)
            / TCP(sport=CPORT, dport=SPORT, flags="PA", seq=cseq, ack=sseq)
            / Raw(data)
        )
        cseq += len(data)
    else:
        pkts.append(
            Ether(src=SRV_MAC, dst=CLI_MAC)
            / IP(src=SRV, dst=CLI)
            / TCP(sport=SPORT, dport=CPORT, flags="PA", seq=sseq, ack=cseq)
            / Raw(data)
        )
        sseq += len(data)


def main() -> None:
    send(greeting, False)
    send(login, True)
    send(ok, False)
    send(query, True)
    # Assign fixed, deterministic timestamps so the pcap is reproducible.
    for i, pkt in enumerate(pkts):
        pkt.time = 1000000000.0 + i
    outfile = Path(__file__).with_suffix("")
    wrpcap(str(outfile), pkts)


if __name__ == "__main__":
    main()
