#!/usr/bin/env python3
"""Generate SMB2 ECHO requests with a unique MID and tree ID each.

Generated with OpenAI Codex, adapted with Claude Opus 4.8 and Claude Sonnet 5.5
to use Scapy.

Zeek's SMB analyzer records a tree ID for every request header, without
requiring a prior tree connect, so per-connection state grows with the number
of messages. The message count exceeds SMB::max_pending_messages in the test so
smb2_discarded_messages_state is raised. ECHO has no handler that removes tree
state, unlike TREE_DISCONNECT.
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap
from scapy.layers.netbios import NBTSession
from scapy.layers.smb2 import SMB2_Header

CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
CLIENT_MAC = "02:00:00:00:00:10"
SERVER_MAC = "02:00:00:00:00:20"
CLIENT_PORT = 49152
SERVER_PORT = 445
BASE_TIME = 1_700_000_000.0

MESSAGE_COUNT = 260
MESSAGES_PER_PACKET = 20
SMB2_ECHO = 13
# ECHO request body (MS-SMB2 2.2.28): StructureSize=4 (u16 LE), Reserved=0 (u16 LE).
ECHO_BODY = b"\x04\x00\x00\x00"


def pkt(is_orig, seq, ack, flags, payload=b""):
    if is_orig:
        src, dst, sport, dport = CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT
        eth_src, eth_dst = CLIENT_MAC, SERVER_MAC
    else:
        src, dst, sport, dport = SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT
        eth_src, eth_dst = SERVER_MAC, CLIENT_MAC

    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(load=payload)
    return p


def smb2_echo(message_id):
    smb = SMB2_Header(
        CreditCharge=1,
        Command=SMB2_ECHO,
        CreditRequest=1,
        MID=message_id,
        PID=1,
        TID=message_id,
        SessionId=1,
    )
    return bytes(NBTSession() / smb / Raw(load=ECHO_BODY))


def build_packets():
    client_seq = 1000
    server_seq = 2000
    packets = [
        pkt(True, client_seq, 0, "S"),
        pkt(False, server_seq, client_seq + 1, "SA"),
        pkt(True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    for first in range(1, MESSAGE_COUNT + 1, MESSAGES_PER_PACKET):
        last = min(first + MESSAGES_PER_PACKET, MESSAGE_COUNT + 1)
        payload = b"".join(smb2_echo(message_id) for message_id in range(first, last))
        packets.append(pkt(True, client_seq, server_seq, "PA", payload))
        client_seq += len(payload)

    packets.append(pkt(True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    return packets


if __name__ == "__main__":
    wrpcap(str(Path(__file__).with_suffix("")), build_packets())
