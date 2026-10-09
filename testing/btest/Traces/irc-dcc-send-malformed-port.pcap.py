#!/usr/bin/env python3

"""
Generates a packet capture with an IRC DCC SEND packet containing an invalid port
number.

Created by GPT-5.5, adapted with Claude Sonnet 5.5 (Anthropic) to use fixed MAC
addresses and timestamps and to write beside the script so the trace is
reproducible.
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

BASE_TIME = 1_700_000_000.0

src_mac = "02:00:00:00:00:01"
dst_mac = "02:00:00:00:00:02"

packets = []

# Common TCP/IP parameters
src_ip = "192.168.1.100"
dst_ip = "192.168.1.200"
src_port = 6667
dst_port = 12345

# DCC SEND with 3 non-numeric ASCII characters as port
irc_msg = b"PRIVMSG victim :DCC SEND file.txt 3232235876 abc 1024\r\n"
pkt = (
    Ether(src=src_mac, dst=dst_mac)
    / IP(src=src_ip, dst=dst_ip)
    / TCP(sport=src_port, dport=dst_port, flags="PA")
    / Raw(load=irc_msg)
)
packets.append(pkt)

for index, p in enumerate(packets):
    p.time = BASE_TIME + index * 0.001

wrpcap(str(Path(__file__).with_suffix("")), packets)
