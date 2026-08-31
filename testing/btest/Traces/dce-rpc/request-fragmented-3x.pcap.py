#!/usr/bin/env python3
"""Generate a DCE-RPC bind + fragmented REQUEST (stub split over three PDUs).

The client binds context id 7 to the endpoint mapper interface
(e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0, transfer syntax NDR 2.0) using
call_id 1, the server accepts, and the client then issues a single RPC call
(call_id 2, opnum 3) whose stub is fragmented across three complete REQUEST
PDUs. All three fragments share call_id 2 (the reassembly key); each REQUEST PDU
repeats the request header fields (alloc_hint, context_id, opnum) and only the
stub data is split. The first REQUEST sets FIRST_FRAG, the last sets LAST_FRAG.

    frag 1 (FIRST): DceRpc5Request(ctx=7, opnum=3) / b'A'*50
    frag 2  (MID) : DceRpc5Request(ctx=7, opnum=3) / b'B'*50
    frag 3 (LAST) : DceRpc5Request(ctx=7, opnum=3) / b'C'*50

Because the bind maps context 7 to a known interface, dissectors that support
DCE-RPC stub reassembly (e.g. Wireshark/tshark) recover a single 150-byte stub
(50*A + 50*B + 50*C). tshark reports:

    [3 Reassembled DCE/RPC Fragments (150 bytes): #6(50), #7(50), #8(50)]

Built with Scapy's high-level DCE/RPC v5 layer, so every PDU is a well-formed
standalone DCE-RPC PDU (verifiable with tshark -O dcerpc).

Generated with Claude Code (Opus 4.8).
"""

from pathlib import Path
from uuid import UUID

from scapy.all import IP, TCP, Ether, wrpcap
from scapy.compat import raw
from scapy.layers.dcerpc import (
    DceRpc5,
    DceRpc5AbstractSyntax,
    DceRpc5Bind,
    DceRpc5BindAck,
    DceRpc5Context,
    DceRpc5PortAny,
    DceRpc5Request,
    DceRpc5Result,
    DceRpc5TransferSyntax,
)

CLIENT_IP = "10.0.0.2"
SERVER_IP = "10.0.0.1"
CLIENT_PORT = 49152
SERVER_PORT = 135  # DCE-RPC

BIND_CALL_ID = 1
CALL_ID = 2  # the fragmented request call; all its fragments share this id
CONTEXT_ID = 7
OPNUM = 3
ALLOC_HINT = 150  # total stub length being assembled

# Endpoint mapper interface v3.0; NDR 2.0 transfer syntax (a Scapy-known name).
EPMAPPER_UUID = UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa")

ETH = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")

# Fixed base timestamp (2021-01-01 00:00:00 UTC) with a fixed per-packet step,
# so packet times don't depend on wall-clock at generation time and the PCAP is
# reproducible byte-for-byte.
BASE_TIME = 1609459200
TIME_STEP = 0.001


def bind_pdu():
    ctx = DceRpc5Context(
        context_id=CONTEXT_ID,
        abstract_syntax=DceRpc5AbstractSyntax(
            if_uuid=EPMAPPER_UUID, if_version=3, if_version_minor=0
        ),
        transfer_syntaxes=[DceRpc5TransferSyntax(if_uuid="NDR 2.0", if_version=2)],
    )
    return DceRpc5(
        ptype=11, pfc_flags="FIRST_FRAG+LAST_FRAG", call_id=BIND_CALL_ID
    ) / DceRpc5Bind(context_elem=[ctx])


def bind_ack_pdu():
    return DceRpc5(
        ptype=12, pfc_flags="FIRST_FRAG+LAST_FRAG", call_id=BIND_CALL_ID
    ) / DceRpc5BindAck(
        sec_addr=DceRpc5PortAny(port_spec=b"\x00"),
        results=[
            DceRpc5Result(
                result=0,
                transfer_syntax=DceRpc5TransferSyntax(if_uuid="NDR 2.0", if_version=2),
            )
        ],
    )


def request_pdu(stub_slice, first=False, last=False):
    flags = []
    if first:
        flags.append("FIRST_FRAG")
    if last:
        flags.append("LAST_FRAG")
    return (
        DceRpc5(ptype=0, pfc_flags="+".join(flags), call_id=CALL_ID)
        / DceRpc5Request(alloc_hint=ALLOC_HINT, cont_id=CONTEXT_ID, opnum=OPNUM)
        / stub_slice
    )


def main():
    seq_c = 100
    seq_s = 200

    def cseg(pdu, seq, ack):
        return (
            ETH
            / IP(src=CLIENT_IP, dst=SERVER_IP)
            / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="PA", seq=seq, ack=ack)
            / pdu
        )

    def sseg(pdu, seq, ack):
        return (
            ETH
            / IP(src=SERVER_IP, dst=CLIENT_IP)
            / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="PA", seq=seq, ack=ack)
            / pdu
        )

    pkts = [
        ETH
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=seq_c),
        ETH
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(
            sport=SERVER_PORT, dport=CLIENT_PORT, flags="SA", seq=seq_s, ack=seq_c + 1
        ),
        ETH
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(
            sport=CLIENT_PORT,
            dport=SERVER_PORT,
            flags="A",
            seq=seq_c + 1,
            ack=seq_s + 1,
        ),
    ]

    frags = [
        request_pdu(b"A" * 50, first=True),
        request_pdu(b"B" * 50),
        request_pdu(b"C" * 50, last=True),
    ]

    cq = seq_c + 1
    sq = seq_s + 1

    bind = bind_pdu()
    pkts.append(cseg(bind, cq, sq))
    cq += len(raw(bind))

    bind_ack = bind_ack_pdu()
    pkts.append(sseg(bind_ack, sq, cq))
    sq += len(raw(bind_ack))

    for frag in frags:
        pkts.append(cseg(frag, cq, sq))
        cq += len(raw(frag))

    for i, pkt in enumerate(pkts):
        pkt.time = BASE_TIME + i * TIME_STEP

    wrpcap(str(Path(__file__).with_suffix("")), pkts)


if __name__ == "__main__":
    main()
