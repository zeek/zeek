#!/usr/bin/env python3
"""
Generated with Claude Opus 4.8.

Generate an SMB1 pcap that feeds many first-only DCE-RPC fragments to Zeek's
DCE/RPC reassembler over a named pipe.

Each DCE-RPC PDU is a connection-oriented REQUEST fragment with only the
PFC_FIRST_FRAG flag set (first frag, but not last) and an empty stub, so the
analyzer opens a flow buffer for its call_id and never closes it. Once more than
DCE_RPC::max_cmd_reassembly (default 20) call_ids are outstanding, the analyzer
raises `too_many_dce_rpc_msgs_in_reassembly` and calls SetSkip(true).

The DCE-RPC fragments are built with Scapy's high-level DCE/RPC v5 layer so that
every PDU is a well-formed REQUEST (the mandatory alloc_hint/context_id/opnum
request header is present in every fragment, only the stub is fragmented). The
SMB1 named-pipe transaction envelope is hand-built because Scapy 2.5.0 has no
SMB1 SMB_COM_TRANSACTION request class; it uses the TransactNmPipe subcommand
and a pipe FID so dissectors recognize the transaction data as DCE-RPC.

The point of interest is what happens to the transactions that follow. SMB
named-pipe delivery must route DCE-RPC bytes through Analyzer::NextStream so the
skip flag is honored; if it calls DeliverStream directly the skip is ignored and
the fragment map keeps growing across every later transaction. The two paths are
distinguishable from a script: the fixed (NextStream) path stops firing the
weird and stops emitting DCE-RPC events once skip is set, while the buggy
(DeliverStream) path keeps going.

To exercise the bug the PDU count just needs to exceed max_cmd_reassembly and be
spread across more than one SMB transaction.
"""

import argparse
import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap
from scapy.compat import raw
from scapy.layers.dcerpc import DceRpc5, DceRpc5Request

CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
CLIENT_MAC = "02:00:00:00:00:10"
SERVER_MAC = "02:00:00:00:00:20"
CLIENT_PORT = 49152
SERVER_PORT = 445

DEFAULT_PDU_COUNT = 100
DEFAULT_PDUS_PER_TRANSACTION = 25
DEFAULT_SEGMENT_SIZE = 1400


def dce_first_fragment(call_id):
    """Build a valid first-only connection-oriented DCE-RPC REQUEST fragment.

    Only PFC_FIRST_FRAG is set (first frag, not last), the required request
    header (alloc_hint/context_id/opnum) is present, and the stub is empty.
    Scapy computes frag_length, so the PDU is always well-formed.
    """
    pdu = DceRpc5(ptype=0, pfc_flags="FIRST_FRAG", call_id=call_id) / DceRpc5Request(
        alloc_hint=0, cont_id=0, opnum=0
    )
    return raw(pdu)


TRANS_TRANSACT_NMPIPE = 0x0026  # SMB1 transaction subcommand for named pipes
PIPE_FID = 0x4000


def smb1_transaction(pipe_data, message_id):
    """Wrap DCE-RPC bytes in an SMB1 named-pipe transaction request.

    The transaction carries the TransactNmPipe subcommand (setup[0]) and a
    pipe FID (setup[1]); together with the "\\PIPE\\" name this is what lets
    dissectors route the transaction data to the DCE-RPC parser.
    """
    smb_header = b"\xffSMB" + struct.pack(
        "<BIBHH8sHHHHH",
        0x25,  # SMB_COM_TRANSACTION
        0,  # status
        0x08,  # flags
        0,  # flags2
        0,  # pid_high
        bytes(8),  # security_features
        0,  # reserved
        1,  # tid
        1,  # pid
        1,  # uid
        message_id & 0xFFFF,  # mid
    )
    name = b"\\PIPE\\\x00"
    # word_count = 14 fixed words + 2 setup words; data starts after the SMB
    # header (32), the word block (1 + 14*2 + 2 setup words = 33), the byte
    # count field (2) and the pipe name.
    data_offset = 32 + 33 + 2 + len(name)
    transaction = struct.pack(
        "<BHHHHBBHIHHHHHBBHH",
        16,  # word_count (14 + 2 setup words)
        0,  # total_param_count
        len(pipe_data),  # total_data_count
        0,  # max_param_count
        0xFFFF,  # max_data_count
        0,  # max_setup_count
        0,  # reserved
        0,  # flags
        0,  # timeout
        0,  # reserved2
        0,  # param_count
        0,  # param_offset
        len(pipe_data),  # data_count
        data_offset,  # data_offset
        2,  # setup_count
        0,  # reserved3
        TRANS_TRANSACT_NMPIPE,  # setup[0]
        PIPE_FID,  # setup[1]
    )
    transaction += struct.pack("<H", len(name) + len(pipe_data)) + name + pipe_data
    smb_message = smb_header + transaction
    # NetBIOS session header: type 0 + 3-byte big-endian length.
    return b"\x00" + len(smb_message).to_bytes(3, "big") + smb_message


def build_packets(pdu_count, pdus_per_transaction, segment_size):
    """Build the full TCP conversation carrying the SMB transactions."""
    eth = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
    eth_s = Ether(src=SERVER_MAC, dst=CLIENT_MAC)

    client_seq = 1000
    server_seq = 5000

    packets = [
        eth
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=client_seq),
        eth_s
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(
            sport=SERVER_PORT,
            dport=CLIENT_PORT,
            flags="SA",
            seq=server_seq,
            ack=client_seq + 1,
        ),
        eth
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(
            sport=CLIENT_PORT,
            dport=SERVER_PORT,
            flags="A",
            seq=client_seq + 1,
            ack=server_seq + 1,
        ),
    ]
    client_seq += 1
    server_seq += 1

    for start in range(0, pdu_count, pdus_per_transaction):
        stop = min(start + pdus_per_transaction, pdu_count)
        pipe_data = b"".join(
            dce_first_fragment(call_id) for call_id in range(start, stop)
        )
        stream = smb1_transaction(pipe_data, start // pdus_per_transaction)
        for offset in range(0, len(stream), segment_size):
            payload = stream[offset : offset + segment_size]
            packets.append(
                eth
                / IP(src=CLIENT_IP, dst=SERVER_IP)
                / TCP(
                    sport=CLIENT_PORT,
                    dport=SERVER_PORT,
                    flags="PA",
                    seq=client_seq,
                    ack=server_seq,
                )
                / Raw(load=payload)
            )
            client_seq += len(payload)

    return packets


def parse_arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    default_out = Path(__file__).with_suffix("")  # strip .py -> ...pcap
    parser.add_argument("--output", type=Path, default=default_out)
    parser.add_argument("--pdu-count", type=int, default=DEFAULT_PDU_COUNT)
    parser.add_argument(
        "--pdus-per-transaction", type=int, default=DEFAULT_PDUS_PER_TRANSACTION
    )
    parser.add_argument("--segment-size", type=int, default=DEFAULT_SEGMENT_SIZE)
    args = parser.parse_args()
    if not 1 <= args.pdu_count <= 0x1_0000_0000:
        parser.error("--pdu-count must be between 1 and 2^32")
    if not 1 <= args.pdus_per_transaction <= 4000:
        parser.error("--pdus-per-transaction must be between 1 and 4000")
    if not 1 <= args.segment_size <= 60000:
        parser.error("--segment-size must be between 1 and 60000")
    return args


def main():
    args = parse_arguments()
    packets = build_packets(
        args.pdu_count, args.pdus_per_transaction, args.segment_size
    )
    wrpcap(str(args.output), packets)
    print(
        f"Wrote {args.pdu_count} fragments in {len(packets)} packets to {args.output}"
    )


if __name__ == "__main__":
    main()
