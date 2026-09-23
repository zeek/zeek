#!/usr/bin/env python3
"""Generate SMB2 WRITE requests with one MID and many file IDs.

Reproducer found internally via GPT 5.5 (Codex), adapted with Claude Opus 4.8
and Claude Sonnet 5.5 to use Scapy.

The requests have no preceding CREATE response. Zeek's SMB script allocates one
fid_map entry per unknown file ID, but the analyzer's generic pending-message
cap is keyed by message ID and does not fire for this shape of traffic.
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap
from scapy.layers.netbios import NBTSession
from scapy.layers.smb2 import SMB2_FILEID, SMB2_Header, SMB2_Write_Request

CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
CLIENT_MAC = "02:00:00:00:00:10"
SERVER_MAC = "02:00:00:00:00:20"
CLIENT_PORT = 49152
SERVER_PORT = 445
BASE_TIME = 1_700_000_000.0

MESSAGE_ID = 7
FILE_COUNT = 260
MESSAGES_PER_PACKET = 20
SMB2_WRITE = 9


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


def smb2_write(file_id):
    smb = SMB2_Header(
        CreditCharge=1,
        Command=SMB2_WRITE,
        CreditRequest=1,
        MID=MESSAGE_ID,
        PID=1,
        TID=1,
        SessionId=1,
    )
    # Zero-byte write, enough to raise smb2_write_request.
    body = SMB2_Write_Request(Offset=0, FileId=SMB2_FILEID(Persistent=file_id))
    return bytes(NBTSession() / smb / body)


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

    for first in range(1, FILE_COUNT + 1, MESSAGES_PER_PACKET):
        last = min(first + MESSAGES_PER_PACKET, FILE_COUNT + 1)
        payload = b"".join(smb2_write(file_id) for file_id in range(first, last))
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
