#!/usr/bin/env python3
"""Generate a pcap with an RDP session whose server certificate is a
zero-length X.509 certificate.

The session mirrors a normal RDP connection sequence:

    TCP handshake
    Client -> Server  X.224 Connection Request (with mstshash cookie)
    Server -> Client  X.224 Connection Confirm
    Client -> Server  MCS Connect-Initial  (GCC ClientData)
    Server -> Client  MCS Connect-Response (GCC ServerData)

The Server MCS Connect-Response carries a Server Security Data block whose
Server Certificate is of type X.509 (version 0x80000002). The certificate
list contains a single entry with cert_len == 0, i.e. a zero-length
certificate. This exercises the RDP analyzer's proc_x509_cert_data() guard
which flags such small certificates via the "rdp_small_x509_certificate"
weird instead of trying to parse them.

The client-side frames and the invariant server prefix bytes are lifted
verbatim from testing/btest/Traces/rdp/rdp-x509.pcap; only the server
certificate (and the enclosing length fields) are rebuilt.

Requires scapy.  Usage:  python3 rdp-zero-length-x509.pcap.py
"""

import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

# ---------------------------------------------------------------------------
# Client-side payloads, reused verbatim from rdp-x509.pcap.
# ---------------------------------------------------------------------------

# X.224 Connection Request + RDP Negotiation Request (Cookie: mstshash=JOHN-PC)
CLIENT_CR = bytes.fromhex(
    "0300002f2ae00000000000436f6f6b69653a206d737473686173683d4a4f484e"
    "2d504320200d0a0100080000000000"
)

# X.224 Connection Confirm + RDP Negotiation Response
SERVER_CC = bytes.fromhex("030000130ed000001234000200080000000000")

# MCS Connect-Initial with GCC ClientData
CLIENT_MCS = bytes.fromhex(
    "030001be02f0807f658201b20401010401010101ff30190201220201020201000201010201000201"
    "010202ffff020102301902010102010102010102010102010002010102020420020102301c0202ff"
    "ff0202fc170202ffff0201010201000201010202ffff02010204820151000500147c000181480008"
    "00100001c00044756361813a01c0ea00040008008007380401ca03aa09040000802500004a004f00"
    "48004e002d00500043002d004c004100500054004f0050000000000004000000000000000c000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000001ca01000000000010000f00ad073300"
    "63003500370031006500640030002d0033003400310035002d0034003700340062002d0061006500"
    "390034002d0037003400650031003500310062000000070000000000000000000000000000000000"
    "00000000000004c00c00150000000000000002c00c001b0000000000000003c03800040000007264"
    "70647200000000008080726470736e640000000000c0636c6970726472000000a0c0647264796e76"
    "6300000080c0"
)

# ---------------------------------------------------------------------------
# Server MCS Connect-Response, rebuilt with a zero-length X.509 certificate.
# ---------------------------------------------------------------------------

# 32-byte serverRandom (reused verbatim from rdp-x509.pcap).
SERVER_RANDOM = bytes.fromhex(
    "9fda0605a0e36f690bff0ca0b121db62dae41b971235375c712b642d8ae3cfa7"
)

# domainParameters SEQUENCE (tag + length + content), reused verbatim.
DOMAIN_PARAMETERS = bytes.fromhex(
    "301a020122020103020100020101020100020101020300fff8020102"
)


def build_server_certificate():
    """Server Certificate: X.509 type, a single zero-length cert.

    version            = 0x80000002 (X.509, temporarily issued bit set)
    X509.num_of_certs  = 1
    X509_Cert_Data.cert_len = 0     (the zero-length certificate)
    """
    version = struct.pack("<I", 0x80000002)
    num_of_certs = struct.pack("<I", 1)
    cert_len = struct.pack("<I", 0)
    cert = b""  # zero-length certificate
    return version + num_of_certs + cert_len + cert


def build_server_security_data():
    cert = build_server_certificate()
    body = b"".join(
        [
            struct.pack("<I", 0x00000002),  # encryptionMethod: 128-bit RC4
            struct.pack("<I", 0x00000002),  # encryptionLevel:  Client Compatible
            struct.pack("<I", len(SERVER_RANDOM)),  # serverRandomLen (32)
            struct.pack("<I", len(cert)),  # serverCertLen
            SERVER_RANDOM,
            cert,
        ]
    )
    header_type = struct.pack("<H", 0x0C02)  # TS_UD_SC_SEC1
    header_len = struct.pack("<H", len(body) + 4)
    return header_type + header_len + body


def build_data_blocks():
    # serverCoreData: version 4.8, no requested protocols.
    server_core = bytes.fromhex("010c0c000400080000000000")
    # serverNetworkData: channel 1003, 4 channels 1004-1007.
    server_network = bytes.fromhex("030c1000eb030400ec03ed03ee03ef03")
    return server_core + server_network + build_server_security_data()


def build_gcc_user_data():
    data_blocks = build_data_blocks()

    # GCC_Server_Connection_Data prefix (Key + connect PDU tag), verbatim.
    connection_data = bytes.fromhex("000500147c00012a")

    # GCC_Server_Create_Response, up to the (PER-encoded) user data length.
    create_response = bytes.fromhex(
        "14"  # extension bit
        "760a"  # node id
        "01"  # tag length
        "01"  # tag
        "00"  # result
        "01"  # number of user data sets
        "c0"  # user data value present
        "00"  # h221 nonstandard length
        "4d63446e"  # h221 nonstandard key: "McDn"
    )
    # PER length with the top bit set (0x8000) as in the original capture.
    user_data_value_length = struct.pack(">H", 0x8000 | len(data_blocks))

    return connection_data + create_response + user_data_value_length + data_blocks


def ber_len_long2(n):
    """Encode a BER length as a 2-octet long form (matches the original pcap)."""
    return bytes([0x82]) + struct.pack(">H", n)


def build_server_mcs():
    user_data = build_gcc_user_data()

    # OCTET STRING wrapping userData, keeping the 2-octet long-form length.
    user_data_octet = b"\x04" + ber_len_long2(len(user_data)) + user_data

    connect_response_content = b"".join(
        [
            bytes.fromhex("0a0100"),  # ENUMERATED result: rt-successful
            bytes.fromhex("020100"),  # INTEGER calledConnectId: 0
            DOMAIN_PARAMETERS,
            user_data_octet,
        ]
    )

    # Connect-Response: application tag 102 (0x7f 0x66), 2-octet long-form length.
    mcs = (
        b"\x7f\x66"
        + ber_len_long2(len(connect_response_content))
        + connect_response_content
    )

    # X.224 Data TPDU (COTP).
    cotp = b"\x02\xf0\x80"

    # TPKT header: version 3, reserved 0, total length.
    tpkt_payload = cotp + mcs
    tpkt = b"\x03\x00" + struct.pack(">H", len(tpkt_payload) + 4)

    return tpkt + tpkt_payload


# ---------------------------------------------------------------------------
# Assemble the TCP session.
# ---------------------------------------------------------------------------

CLIENT_IP, SERVER_IP = "192.168.1.1", "192.168.1.2"
CLIENT_MAC, SERVER_MAC = "00:17:c5:10:15:40", "00:50:56:8c:fc:10"
CLIENT_PORT, SERVER_PORT = 54990, 3389


def main():
    out = Path(__file__).with_suffix("")

    server_mcs = build_server_mcs()

    c_seq = 1  # client ISN + 1 (post handshake)
    s_seq = 1  # server ISN + 1 (post handshake)

    def c2s(flags, payload=b""):
        nonlocal c_seq
        pkt = (
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=CLIENT_IP, dst=SERVER_IP)
            / TCP(
                sport=CLIENT_PORT, dport=SERVER_PORT, flags=flags, seq=c_seq, ack=s_seq
            )
        )
        if payload:
            pkt /= Raw(load=payload)
        c_seq += len(payload)
        return pkt

    def s2c(flags, payload=b""):
        nonlocal s_seq
        pkt = (
            Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            / IP(src=SERVER_IP, dst=CLIENT_IP)
            / TCP(
                sport=SERVER_PORT, dport=CLIENT_PORT, flags=flags, seq=s_seq, ack=c_seq
            )
        )
        if payload:
            pkt /= Raw(load=payload)
        s_seq += len(payload)
        return pkt

    packets = []

    # --- TCP three-way handshake ---
    syn = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP)
        / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=0)
    )
    packets.append(syn)
    synack = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="SA", seq=0, ack=1)
    )
    packets.append(synack)
    packets.append(c2s("A"))  # final ACK

    # --- RDP connection sequence ---
    packets.append(c2s("PA", CLIENT_CR))  # X.224 Connection Request
    packets.append(s2c("PA", SERVER_CC))  # X.224 Connection Confirm
    packets.append(c2s("PA", CLIENT_MCS))  # MCS Connect-Initial (ClientData)
    packets.append(s2c("PA", server_mcs))  # MCS Connect-Response (ServerData)

    wrpcap(str(out), packets)
    print(f"Wrote {len(packets)} packets to {out}")
    print(f"Server MCS Connect-Response payload: {len(server_mcs)} bytes")


if __name__ == "__main__":
    main()
