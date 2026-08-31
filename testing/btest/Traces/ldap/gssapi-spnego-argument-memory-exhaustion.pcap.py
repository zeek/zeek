#!/usr/bin/env python3
"""
Generate an LDAP SASL bind pcap exercising the SPNEGO argument validation
added to the GSSAPI analyzer.

Two TCP connections are produced on separate client ports:

  1. A NegTokenResp with a duplicate negState argument (index 0 repeated),
     which triggers the "invalid duplicate or unknown SPNEGO argument"
     binpac exception.

  2. A well-formed NegTokenResp carrying negState and supportedMech that
     the analyzer should parse without error.

Generated with Claude Opus 4.6, adapted with Claude Opus 4.8 to use Scapy.
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap
from scapy.layers.ldap import (
    LDAP,
    LDAP_Authentication_SaslCredentials,
    LDAP_BindRequest,
)
from scapy.layers.spnego import (
    SPNEGO_MechType,
    SPNEGO_negToken,
    SPNEGO_negTokenResp,
)

CLIENT_IP = "192.0.2.1"
SERVER_IP = "192.0.2.2"
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
SERVER_PORT = 389
BASE_TIME = 1_700_000_000.0

# OID 1.2.840.113554.1.2.2 (Kerberos 5).
KRB5_OID = "1.2.840.113554.1.2.2"


def neg_token_resp_duplicate():
    """NegTokenResp with a duplicate negState argument (index 0 twice).

    Scapy's ASN.1 encoder will not emit a duplicate SPNEGO argument, so this
    intentionally malformed token is assembled by hand from the deterministic
    negState element Scapy produces. The negState TLV (a0 03 0a 01 00) is
    extracted by stripping the two-byte SEQUENCE header, then wrapped twice
    inside the negTokenResp SEQUENCE and the [1] context tag. All lengths are
    below 0x80, so a single-byte length encoding is sufficient.
    """
    neg_state = bytes(SPNEGO_negTokenResp(negState=0))[2:]

    def ber_tlv(tag, value):
        return bytes([tag, len(value)]) + value

    return ber_tlv(0xA1, ber_tlv(0x30, neg_state + neg_state))


def neg_token_resp_valid():
    """Well-formed NegTokenResp with negState and supportedMech."""
    token = SPNEGO_negTokenResp(
        negState=0,
        supportedMech=SPNEGO_MechType(oid=KRB5_OID),
    )
    return bytes(SPNEGO_negToken(token=token))


def ldap_bind(gssapi_token):
    """Wrap a GSSAPI token in an LDAP SASL bind request."""
    sasl = LDAP_Authentication_SaslCredentials(
        mechanism="GSSAPI",
        credentials=gssapi_token,
    )
    bind = LDAP_BindRequest(version=3, bind_name="", authentication=sasl)
    return bytes(LDAP(messageID=1, protocolOp=bind))


def pkt(client_port, is_orig, seq, ack, flags, payload=b""):
    if is_orig:
        src, dst, sport, dport = CLIENT_IP, SERVER_IP, client_port, SERVER_PORT
        eth_src, eth_dst = CLIENT_MAC, SERVER_MAC
    else:
        src, dst, sport, dport = SERVER_IP, CLIENT_IP, SERVER_PORT, client_port
        eth_src, eth_dst = SERVER_MAC, CLIENT_MAC
    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    return p


def build_connection(client_port, gssapi_token):
    """Build a full TCP connection carrying an LDAP SASL bind."""
    client_seq, server_seq = 1000, 2000
    packets = [
        pkt(client_port, True, client_seq, 0, "S"),
        pkt(client_port, False, server_seq, client_seq + 1, "SA"),
        pkt(client_port, True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    request = ldap_bind(gssapi_token)
    packets.append(pkt(client_port, True, client_seq, server_seq, "PA", request))
    client_seq += len(request)

    # Clean FIN/ACK teardown, client-initiated (a FIN consumes one seq).
    packets.append(pkt(client_port, True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(client_port, False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(client_port, True, client_seq, server_seq, "A"))

    return packets


def main():
    packets = []
    packets += build_connection(40000, neg_token_resp_duplicate())
    packets += build_connection(40001, neg_token_resp_valid())

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)
    print(f"Wrote {len(packets)} packets")


if __name__ == "__main__":
    main()
