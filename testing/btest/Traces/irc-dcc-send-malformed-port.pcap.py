#!/usr/bin/env python3

"""
Generates a packet capture with an IRC DCC SEND packet containing an invalid port
number.

Created by GPT-5.5.
"""

from scapy.all import IP, TCP, Ether, Raw, wrpcap

packets = []

# Common TCP/IP parameters
src_ip = "192.168.1.100"
dst_ip = "192.168.1.200"
src_port = 6667
dst_port = 12345

# DCC SEND with 3 non-numeric ASCII characters as port
irc_msg = b"PRIVMSG victim :DCC SEND file.txt 3232235876 abc 1024\r\n"
pkt = (
    Ether()
    / IP(src=src_ip, dst=dst_ip)
    / TCP(sport=src_port, dport=dst_port, flags="PA")
    / Raw(load=irc_msg)
)
packets.append(pkt)

wrpcap("irc-dcc-send-malformed-port.pcap", packets)
print("Wrote irc-dcc-send-malformed-port.pcap")
