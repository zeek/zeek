#!/usr/bin/env python3
# Generates a chain of SMB AndX commands where the offset advances.
# Created by Claude Opus 4.6.
import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap
from scapy.layers.netbios import NBTSession
from scapy.layers.smb import SMB_Header

OUT = Path(__file__).resolve().parent
COUNT = 12
SMB_HDR_LEN = 32
ELEM_LEN = 7


def make_andx_chain():
    elems = b""
    for i in range(COUNT):
        next_offset = SMB_HDR_LEN + (i + 1) * ELEM_LEN
        next_cmd = 0x74 if i < COUNT - 1 else 0xFF
        elems += struct.pack("<BBBH H", 2, next_cmd, 0, next_offset, 0)
    return elems


def make_payload():
    header = SMB_Header(
        Command="SMB_COM_LOGOFF_ANDX", Flags=0x18, TID=1, PIDLow=0x1234, MID=1
    )
    smb_data = bytes(header) + make_andx_chain()
    return bytes(NBTSession() / Raw(load=smb_data))


def write_pcap(payload):
    c = ("10.0.1.1", 52000)
    s = ("10.0.1.2", 445)
    seq_c = 1000
    seq_s = 2000
    pkts = [
        Ether()
        / IP(src=c[0], dst=s[0])
        / TCP(sport=c[1], dport=s[1], flags="S", seq=seq_c),
        Ether()
        / IP(src=s[0], dst=c[0])
        / TCP(sport=s[1], dport=c[1], flags="SA", seq=seq_s, ack=seq_c + 1),
        Ether()
        / IP(src=c[0], dst=s[0])
        / TCP(sport=c[1], dport=s[1], flags="A", seq=seq_c + 1, ack=seq_s + 1),
    ]

    seq = seq_c + 1
    pkts.append(
        Ether()
        / IP(src=c[0], dst=s[0])
        / TCP(sport=c[1], dport=s[1], flags="PA", seq=seq, ack=seq_s + 1)
        / Raw(load=payload)
    )

    wrpcap(str(OUT / "smb1-logoff-andx-advance.pcap"), pkts)


if __name__ == "__main__":
    write_pcap(make_payload())
