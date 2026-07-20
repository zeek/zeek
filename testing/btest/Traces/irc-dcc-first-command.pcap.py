#!/usr/bin/env python3

"""
Generates a pcap containing an IRC control connection where the first IRC command seen
is a DCC SEND PRIVMSG, followed by the corresponding DCC data connection.

Created by GPT-5.5.
"""

import sys
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


class FlowBuilder:
    def __init__(self):
        self.time = 1.0

    def packet(self, src, dst, sport, dport, seq, ack, flags, payload=b""):
        ether_src = CLIENT_MAC if src == CLIENT else SERVER_MAC
        ether_dst = SERVER_MAC if src == CLIENT else CLIENT_MAC

        pkt = (
            Ether(src=ether_src, dst=ether_dst)
            / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
        )

        if payload:
            pkt = pkt / Raw(payload)

        pkt.time = self.time
        self.time += 0.001
        return pkt


def build_packets():
    builder = FlowBuilder()
    packets = []

    irc_client_port = 12345
    irc_server_port = 6667
    client_seq = 1000
    server_seq = 2000

    packets.append(
        builder.packet(
            CLIENT, SERVER, irc_client_port, irc_server_port, client_seq, 0, "S"
        )
    )
    client_seq += 1
    packets.append(
        builder.packet(
            SERVER,
            CLIENT,
            irc_server_port,
            irc_client_port,
            server_seq,
            client_seq,
            "SA",
        )
    )
    server_seq += 1
    packets.append(
        builder.packet(
            CLIENT,
            SERVER,
            irc_client_port,
            irc_server_port,
            client_seq,
            server_seq,
            "A",
        )
    )

    dcc_offer = b"PRIVMSG bob :\x01DCC SEND hello.txt 167772161 5555 12\x01\r\n"
    packets.append(
        builder.packet(
            CLIENT,
            SERVER,
            irc_client_port,
            irc_server_port,
            client_seq,
            server_seq,
            "PA",
            dcc_offer,
        )
    )
    client_seq += len(dcc_offer)
    packets.append(
        builder.packet(
            SERVER,
            CLIENT,
            irc_server_port,
            irc_client_port,
            server_seq,
            client_seq,
            "A",
        )
    )

    dcc_client_port = 23456
    dcc_server_port = 5555
    dcc_client_seq = 3000
    dcc_server_seq = 4000

    packets.append(
        builder.packet(
            SERVER, CLIENT, dcc_client_port, dcc_server_port, dcc_client_seq, 0, "S"
        )
    )
    dcc_client_seq += 1
    packets.append(
        builder.packet(
            CLIENT,
            SERVER,
            dcc_server_port,
            dcc_client_port,
            dcc_server_seq,
            dcc_client_seq,
            "SA",
        )
    )
    dcc_server_seq += 1
    packets.append(
        builder.packet(
            SERVER,
            CLIENT,
            dcc_client_port,
            dcc_server_port,
            dcc_client_seq,
            dcc_server_seq,
            "A",
        )
    )

    data = b"hello world\n"
    packets.append(
        builder.packet(
            CLIENT,
            SERVER,
            dcc_server_port,
            dcc_client_port,
            dcc_server_seq,
            dcc_client_seq,
            "PA",
            data,
        )
    )
    dcc_server_seq += len(data)
    packets.append(
        builder.packet(
            SERVER,
            CLIENT,
            dcc_client_port,
            dcc_server_port,
            dcc_client_seq,
            dcc_server_seq,
            "A",
        )
    )

    return packets


def main():
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_suffix("")
    wrpcap(str(output), build_packets())


if __name__ == "__main__":
    main()
