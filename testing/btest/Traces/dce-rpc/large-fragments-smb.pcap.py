#!/usr/bin/env python3
"""Generate SMB2 named-pipe traffic carrying srvsvc NetrShareEnum with large
DCE-RPC response fragments (reproducer for Zeek issue #5975).

THIS TRACE IS SYNTHETIC. It is not a capture of a real client and server and
was not produced by any Windows or Samba implementation. It is built to be a
well-formed, plausible exchange that tshark dissects without complaints, but
it deliberately deviates from real traffic where that is needed to exercise
Zeek's DCE-RPC fragment handling:

  * Fragments are 60000 bytes. Both sides claim max_xmit_frag/max_recv_frag of
    65535 in the bind. DCE-RPC permits this (frag_length is 16 bit), but real
    Windows clients and servers typically negotiate 4280 or 5840 bytes.
  * There is no authentication. The session setup is a single exchange with an
    empty security buffer, where a real client and server would run an
    NTLMSSP or Kerberos exchange over several round trips. There is also no
    signing or encryption.
  * Server and client behavior is idealized: every SMB2 Read returns exactly
    one DCE-RPC fragment, credits are not tracked realistically, and
    timestamps/GUIDs/IDs are fixed constants.
  * The share list is generated filler ("share-0001", "Department share
    0001", ...), not the shares of an actual server.

What the trace does contain, as far as tshark's dissectors are concerned:
SMB2 negotiate, a session setup, a tree connect to \\\\FILESRV01\\IPC$,
a create of the \\srvsvc pipe, a srvsvc bind (4b324fc8-1670-01d3-1278-5a47bf6ee188
v3.0), and a NetrShareEnum (opnum 15, level 1) call whose NDR response is split
over three fragments (FIRST, MIDDLE, LAST), the first two being 60000 bytes
each. The large call is sandwiched between two identical, small
NetrServerGetInfo calls (opnum 21, level 100; single-fragment request and
response, trivially distinguishable from the NetrShareEnum transfer). The first
is analyzed regardless; the second shows whether analysis continues after the
large transfer.

Zeek's DCE-RPC analyzer reassembles the fragmented response and enforces
DCE_RPC::max_frag_data. Originally (issue #5975), exceeding the limit raised
too_much_dce_rpc_fragment_data and called SetSkip(), which the SMB named-pipe
delivery honored, so the second NetrServerGetInfo call was no longer analyzed.
The analyzer now discards the oversized fragment state instead and keeps
analyzing the connection. With a limit smaller than the reassembled
NetrShareEnum response (about 130 KB) the large call is dropped while both
NetrServerGetInfo calls are still seen. With a larger (or zero, meaning
unlimited) limit all three calls are seen.

Written with Claude Sonnet 5.5 using Scapy, including its SMB2 and MS-SRVS
NDR layers.
"""

import gzip
import struct
from pathlib import Path
from uuid import UUID

from scapy.all import IP, TCP, Ether, Raw, conf, wrpcap
from scapy.compat import raw
from scapy.layers.dcerpc import (
    DceRpc5,
    DceRpc5AbstractSyntax,
    DceRpc5Bind,
    DceRpc5BindAck,
    DceRpc5Context,
    DceRpc5PortAny,
    DceRpc5Request,
    DceRpc5Response,
    DceRpc5Result,
    DceRpc5TransferSyntax,
    NDRUnion,
)
from scapy.layers.msrpce.raw.ms_srvs import (
    LPSERVER_INFO_100,
    LPSHARE_ENUM_STRUCT,
    LPSHARE_INFO_1,
    SHARE_INFO_1_CONTAINER,
    NetrServerGetInfo_Request,
    NetrServerGetInfo_Response,
    NetrShareEnum_Request,
    NetrShareEnum_Response,
)
from scapy.layers.netbios import NBTSession
from scapy.layers.smb2 import (
    SMB2_Close_Request,
    SMB2_Close_Response,
    SMB2_Create_Request,
    SMB2_Create_Response,
    SMB2_Header,
    SMB2_Negotiate_Protocol_Request,
    SMB2_Negotiate_Protocol_Response,
    SMB2_Read_Request,
    SMB2_Read_Response,
    SMB2_Session_Logoff_Request,
    SMB2_Session_Logoff_Response,
    SMB2_Session_Setup_Request,
    SMB2_Session_Setup_Response,
    SMB2_Tree_Connect_Request,
    SMB2_Tree_Connect_Response,
    SMB2_Tree_Disconnect_Request,
    SMB2_Tree_Disconnect_Response,
    SMB2_Write_Request,
    SMB2_Write_Response,
)

# The bind negotiates NDR 2.0 (32-bit), so serialize stubs that way, not NDR64.
conf.ndr64 = False

CLIENT = "192.0.2.10"
SERVER = "192.0.2.20"
CLIENT_PORT = 49152
SERVER_PORT = 445
BASE_TIME = 1_700_000_000.0
SEGMENT_SIZE = 1460

SRVSVC_UUID = UUID("4b324fc8-1670-01d3-1278-5a47bf6ee188")
CONTEXT_ID = 0
OPNUM_NET_SHARE_ENUM = 15
OPNUM_NET_SERVER_GET_INFO = 21
MAX_FRAG = 65535
FRAGMENT_SIZE = 60000  # frag_length of the non-final response fragments
RESPONSE_HEADER_SIZE = 24
LARGE_SHARE_COUNT = 1250  # sized for two full fragments plus a shorter last one

SERVER_GUID = "6d0f6b3a-8c1b-4e9a-9a52-2f2a9c3b1d01"
CLIENT_GUID = "0b1f4a92-5d3c-4c64-8b3e-7a3f1e0d9c11"
SESSION_ID = 0x0000110000000015
TREE_ID = 1
FILE_ID = struct.pack("<QQ", 0x0000000100000005, 0x0000000000000005)
# 2023-11-14 22:13:20 UTC as a FILETIME (100ns ticks since 1601-01-01).
FILETIME = (1_700_000_000 + 11_644_473_600) * 10_000_000


# SMB2 commands.
NEGOTIATE, SESSION_SETUP, LOGOFF, TREE_CONNECT, TREE_DISCONNECT = 0, 1, 2, 3, 4
CREATE, CLOSE, READ, WRITE = 5, 6, 8, 9


def pkt(is_orig, seq, ack, flags, payload=b""):
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, CLIENT_PORT, SERVER_PORT
        eth_src, eth_dst = "02:00:00:00:00:10", "02:00:00:00:00:20"
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, CLIENT_PORT
        eth_src, eth_dst = "02:00:00:00:00:20", "02:00:00:00:00:10"
    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    return p


def bind_pdu(call_id):
    ctx = DceRpc5Context(
        cont_id=CONTEXT_ID,
        abstract_syntax=DceRpc5AbstractSyntax(if_uuid=SRVSVC_UUID, if_version=3),
        transfer_syntaxes=[DceRpc5TransferSyntax(if_uuid="NDR 2.0", if_version=2)],
    )
    return DceRpc5(
        ptype=11, pfc_flags="PFC_FIRST_FRAG+PFC_LAST_FRAG", call_id=call_id
    ) / DceRpc5Bind(max_xmit_frag=MAX_FRAG, max_recv_frag=MAX_FRAG, context_elem=[ctx])


def bind_ack_pdu(call_id):
    return DceRpc5(
        ptype=12, pfc_flags="PFC_FIRST_FRAG+PFC_LAST_FRAG", call_id=call_id
    ) / DceRpc5BindAck(
        max_xmit_frag=MAX_FRAG,
        max_recv_frag=MAX_FRAG,
        assoc_group_id=0x1234,
        sec_addr=DceRpc5PortAny(port_spec=b"\\PIPE\\srvsvc\x00"),
        results=[
            DceRpc5Result(
                result=0,
                transfer_syntax=DceRpc5TransferSyntax(if_uuid="NDR 2.0", if_version=2),
            )
        ],
    )


def request_pdu(call_id, opnum, stub):
    return (
        DceRpc5(ptype=0, pfc_flags="PFC_FIRST_FRAG+PFC_LAST_FRAG", call_id=call_id)
        / DceRpc5Request(alloc_hint=len(stub), cont_id=CONTEXT_ID, opnum=opnum)
        / stub
    )


def response_pdus(call_id, stub, fragment_size):
    """Split stub into response PDUs of at most fragment_size bytes each."""
    chunk = fragment_size - RESPONSE_HEADER_SIZE
    pieces = [stub[i : i + chunk] for i in range(0, len(stub), chunk)]
    pdus = []
    for index, piece in enumerate(pieces):
        flags = []
        if index == 0:
            flags.append("PFC_FIRST_FRAG")
        if index == len(pieces) - 1:
            flags.append("PFC_LAST_FRAG")
        pdus.append(
            DceRpc5(ptype=2, pfc_flags="+".join(flags), call_id=call_id)
            / DceRpc5Response(alloc_hint=len(stub) if index == 0 else 0, cont_id=0)
            / piece
        )
    return pdus


def share_enum_request_stub():
    return raw(
        NetrShareEnum_Request(
            ServerName="\\\\FILESRV01",
            InfoStruct=LPSHARE_ENUM_STRUCT(
                Level=1,
                ShareInfo=NDRUnion(tag=1, value=SHARE_INFO_1_CONTAINER(Buffer=[])),
            ),
            PreferedMaximumLength=0xFFFFFFFF,
            ResumeHandle=None,
        )
    )


def share_enum_response_stub(count):
    shares = [
        LPSHARE_INFO_1(
            shi1_netname=f"share-{i:04d}",
            shi1_type=0,  # STYPE_DISKTREE
            shi1_remark=f"Department share {i:04d}",
        )
        for i in range(count)
    ]
    return raw(
        NetrShareEnum_Response(
            InfoStruct=LPSHARE_ENUM_STRUCT(
                Level=1,
                ShareInfo=NDRUnion(tag=1, value=SHARE_INFO_1_CONTAINER(Buffer=shares)),
            ),
            TotalEntries=count,
            ResumeHandle=None,
            status=0,
        )
    )


def server_get_info_request_stub():
    return raw(NetrServerGetInfo_Request(ServerName="\\\\FILESRV01", Level=100))


def server_get_info_response_stub():
    return raw(
        NetrServerGetInfo_Response(
            InfoStruct=NDRUnion(
                tag=100,
                value=LPSERVER_INFO_100(sv100_platform_id=500, sv100_name="FILESRV01"),
            ),
            status=0,
        )
    )


def smb2(command, mid, body, is_response=False, status=0, tid=0, session_id=0):
    header = SMB2_Header(
        Command=command,
        MID=mid,
        Status=status,
        CreditRequest=32 if is_response else 1,
        Flags="SMB2_FLAGS_SERVER_TO_REDIR" if is_response else 0,
        TID=tid,
        SessionId=session_id,
    )
    return bytes(NBTSession() / header / body)


def build_packets():
    state = {"c": 1000, "s": 5000}
    packets = [
        pkt(True, state["c"], 0, "S"),
        pkt(False, state["s"], state["c"] + 1, "SA"),
        pkt(True, state["c"] + 1, state["s"] + 1, "A"),
    ]
    state["c"] += 1
    state["s"] += 1

    def send(is_orig, payload):
        # Segment large SMB messages the way TCP would.
        key, other = ("c", "s") if is_orig else ("s", "c")
        for off in range(0, len(payload), SEGMENT_SIZE):
            chunk = payload[off : off + SEGMENT_SIZE]
            packets.append(pkt(is_orig, state[key], state[other], "PA", chunk))
            state[key] += len(chunk)

    mid = 0

    def exchange(command, request, response, status=0, tid=0, session_id=0):
        nonlocal mid
        send(True, smb2(command, mid, request, False, 0, tid, session_id))
        send(False, smb2(command, mid, response, True, status, tid, session_id))
        mid += 1

    exchange(
        NEGOTIATE,
        SMB2_Negotiate_Protocol_Request(
            Dialects=[0x0202, 0x0210, 0x0300, 0x0302],
            ClientGUID=CLIENT_GUID,
            SecurityMode=1,
        ),
        SMB2_Negotiate_Protocol_Response(
            DialectRevision=0x0302,
            GUID=SERVER_GUID,
            SecurityMode=1,
            Capabilities=0x7,
            MaxTransactionSize=8388608,
            MaxReadSize=8388608,
            MaxWriteSize=8388608,
            ServerTime=FILETIME,
            ServerStartTime=FILETIME - 86_400 * 10_000_000,
        ),
    )

    exchange(
        SESSION_SETUP,
        SMB2_Session_Setup_Request(),
        SMB2_Session_Setup_Response(),
        session_id=SESSION_ID,
    )

    exchange(
        TREE_CONNECT,
        SMB2_Tree_Connect_Request(Buffer=[("Path", "\\\\FILESRV01\\IPC$")]),
        SMB2_Tree_Connect_Response(ShareType=2, MaximalAccess=0x001F01FF),  # PIPE
        tid=TREE_ID,
        session_id=SESSION_ID,
    )

    exchange(
        CREATE,
        SMB2_Create_Request(
            DesiredAccess=0x0012019F,
            ShareAccess=7,
            CreateDisposition=1,  # FILE_OPEN
            CreateOptions=0x40,  # FILE_NON_DIRECTORY_FILE
            ImpersonationLevel=2,
            Buffer=[("Name", "srvsvc")],
        ),
        SMB2_Create_Response(
            CreateAction=1,
            FileId=FILE_ID,
            CreationTime=FILETIME,
            LastAccessTime=FILETIME,
            LastWriteTime=FILETIME,
            ChangeTime=FILETIME,
        ),
        tid=TREE_ID,
        session_id=SESSION_ID,
    )

    def write(pipe_data):
        exchange(
            WRITE,
            SMB2_Write_Request(FileId=FILE_ID, Buffer=[("Data", pipe_data)]),
            SMB2_Write_Response(Count=len(pipe_data)),
            tid=TREE_ID,
            session_id=SESSION_ID,
        )

    def read(pipe_data):
        exchange(
            READ,
            SMB2_Read_Request(FileId=FILE_ID, Length=65536, MinimumCount=0),
            SMB2_Read_Response(Buffer=[("Data", pipe_data)]),
            tid=TREE_ID,
            session_id=SESSION_ID,
        )

    write(raw(bind_pdu(1)))
    read(raw(bind_ack_pdu(1)))

    def server_get_info(call_id):
        write(
            raw(
                request_pdu(
                    call_id, OPNUM_NET_SERVER_GET_INFO, server_get_info_request_stub()
                )
            )
        )
        for pdu in response_pdus(
            call_id, server_get_info_response_stub(), FRAGMENT_SIZE
        ):
            read(raw(pdu))

    # Small call (NetrServerGetInfo, level 100) before the large transfer. This
    # is analyzed regardless.
    server_get_info(2)

    # NetrShareEnum with a large response split into 60000 byte fragments.
    write(raw(request_pdu(3, OPNUM_NET_SHARE_ENUM, share_enum_request_stub())))
    for pdu in response_pdus(
        3, share_enum_response_stub(LARGE_SHARE_COUNT), FRAGMENT_SIZE
    ):
        read(raw(pdu))

    # Same small call again, only analyzed if the large fragments didn't cause
    # the analyzer to be skipped.
    server_get_info(4)

    exchange(
        CLOSE,
        SMB2_Close_Request(FileId=FILE_ID),
        SMB2_Close_Response(),
        tid=TREE_ID,
        session_id=SESSION_ID,
    )
    exchange(
        TREE_DISCONNECT,
        SMB2_Tree_Disconnect_Request(),
        SMB2_Tree_Disconnect_Response(),
        tid=TREE_ID,
        session_id=SESSION_ID,
    )
    exchange(
        LOGOFF,
        SMB2_Session_Logoff_Request(),
        SMB2_Session_Logoff_Response(),
        session_id=SESSION_ID,
    )

    # Clean teardown, initiated by the originator.
    packets.append(pkt(True, state["c"], state["s"], "FA"))
    state["c"] += 1
    packets.append(pkt(False, state["s"], state["c"], "FA"))
    state["s"] += 1
    packets.append(pkt(True, state["c"], state["s"], "A"))
    return packets


def main():
    packets = build_packets()
    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    # Highly compressible (repetitive share names); gzip reproducibly.
    out = Path(__file__).with_suffix(".gz")
    with gzip.GzipFile(out, "wb", mtime=0) as f:
        wrpcap(f, packets)


if __name__ == "__main__":
    main()
