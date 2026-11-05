#!/usr/bin/env python3
"""HTTP request to whatsmyip.com tunneled over L2TPv3 inside a UDP session.

Builds a UDP-encapsulated L2TPv3 (RFC 3931) tunnel between two LCCEs on
port 1701, carrying a full control plane and a data plane:

  * Control plane: control-connection setup (SCCRQ / SCCRP / SCCCN), session
    setup for an Ethernet pseudowire in each direction (ICRQ / ICRP / ICCN),
    and teardown (CDN / StopCCN). The session-setup messages advertise each
    direction's Local Session ID together with Pseudowire Type = Ethernet and
    no L2-Specific Sublayer, so an independent dissector (e.g. tshark) can map
    each data Session ID to an Ethernet pseudowire and dissect the tunneled
    frames all the way up to HTTP.
  * Data plane: each UDP datagram carries one L2TPv3 data message whose payload
    is an Ethernet pseudowire frame (RFC 4719). The tunneled frames form a
    complete inner TCP flow: a client at 10.1.1.100 does a plain HTTP GET / with
    "Host: whatsmyip.com" to a server at 203.0.113.50:80, which answers 200 OK,
    and the connection is torn down cleanly.

The outer transport is connectionless UDP, so there is no outer handshake; the
inner TCP flow is well-formed, and the L2TP control connection and session are
opened and closed cleanly around the data.

Scapy's scapy.layers.l2tp.L2TP only models L2TPv2 (16-bit tunnel/session IDs),
so the L2TPv3-over-UDP control and data headers and the control-message AVPs
are written as documented fixed blobs; the outer carrier and the entire inner
frame use Scapy's high-level API (which computes all lengths and checksums).

Generates an L2TPv3-over-UDP trace carrying a tunneled HTTP request. Written
with claude-opus-4-8 using Scapy (disclose AI assistance per AI_POLICY.md).
"""

import struct
from pathlib import Path

from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap

# Outer tunnel endpoints (LCCEs). Both use the registered L2TP UDP port 1701.
# A is the tunnel initiator; B is the responder.
LCCE_A = "192.0.2.1"
LCCE_B = "192.0.2.2"
L2TP_PORT = 1701
LCCE_A_MAC = "02:00:00:00:00:01"
LCCE_B_MAC = "02:00:00:00:00:02"

# Control Connection IDs each LCCE assigns to itself (nonzero).
CCID_A = 0x11111111
CCID_B = 0x22222222

# Per-direction pseudowire Session IDs (nonzero; 0 is reserved for control).
# The Session ID in a data message is the one assigned by the *receiver*: a
# data message A->B carries B's Local Session ID, and vice versa.
SESSION_A_TO_B = 0x1A2B3C4D  # B's Local Session ID (advertised in ICRP)
SESSION_B_TO_A = 0x4D3C2B1A  # A's Local Session ID (advertised in ICRQ)

# Inner Ethernet pseudowire endpoints.
INNER_CLIENT = "10.1.1.100"
INNER_SERVER = "203.0.113.50"  # whatsmyip.com
INNER_CLIENT_MAC = "02:aa:aa:aa:aa:aa"
INNER_SERVER_MAC = "02:bb:bb:bb:bb:bb"
INNER_CLIENT_PORT = 49152
INNER_SERVER_PORT = 80

BASE_TIME = 1_700_000_000.0

# L2TPv3 control message types (RFC 3931).
SCCRQ, SCCRP, SCCCN, STOPCCN = 1, 2, 3, 4
ICRQ, ICRP, ICCN, CDN = 10, 11, 12, 14

# L2TPv3 control message AVP attribute types (RFC 3931).
AVP_MESSAGE_TYPE = 0
AVP_RESULT_CODE = 1
AVP_ASSIGNED_CCID = 61
AVP_PW_CAPABILITIES = 62
AVP_LOCAL_SESSION_ID = 63
AVP_REMOTE_SESSION_ID = 64
AVP_PW_TYPE = 68
AVP_L2_SPECIFIC_SUBLAYER = 69
AVP_DATA_SEQUENCING = 70
AVP_CIRCUIT_STATUS = 71

PW_TYPE_ETHERNET = 0x0005  # IANA L2TPv3 Pseudowire Type for Ethernet
CIRCUIT_STATUS_ACTIVE_NEW = 0x0003  # bit0 Active, bit1 New

HTTP_REQUEST = (
    b"GET / HTTP/1.1\r\n"
    b"Host: whatsmyip.com\r\n"
    b"User-Agent: curl/8.4.0\r\n"
    b"Accept: */*\r\n"
    b"\r\n"
)
HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 14\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"203.0.113.100\n"
)


def outer(a_to_b, payload):
    """Wrap an L2TP message in its UDP/IP/Ethernet carrier between the LCCEs."""
    if a_to_b:
        eth_src, eth_dst, ip_src, ip_dst = LCCE_A_MAC, LCCE_B_MAC, LCCE_A, LCCE_B
    else:
        eth_src, eth_dst, ip_src, ip_dst = LCCE_B_MAC, LCCE_A_MAC, LCCE_B, LCCE_A
    return (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=ip_src, dst=ip_dst)
        / UDP(sport=L2TP_PORT, dport=L2TP_PORT)
        / Raw(payload)
    )


def avp(attr_type, value):
    """Encode one mandatory (M bit set), IETF (Vendor ID 0) control AVP.

    First 16 bits: M bit (0x8000) | H bit (0) | reserved (0) | 10-bit Length,
    where Length counts the 6-byte AVP header plus the value. Then the 16-bit
    Vendor ID (0 = IETF) and 16-bit Attribute Type, then the value.
    """
    first = 0x8000 | (len(value) + 6)
    return struct.pack("!HHH", first, 0, attr_type) + value


def message_type_avp(msg_type):
    return avp(AVP_MESSAGE_TYPE, struct.pack("!H", msg_type))


def control(a_to_b, recipient_ccid, ns, nr, avps):
    """Build an L2TPv3-over-UDP control message (RFC 3931 section 4.1.2.1).

    Byte 0: flags, T=1 (control) | L=1 (length present) | S=1 (sequence
    present) => 0xC8, all other flags clear.
    Byte 1: low nibble is Version = 3.
    Bytes 2-3: Length of the whole control message (12-byte header + AVPs).
    Bytes 4-7: Control Connection ID (the recipient's assigned ID; 0 when not
    yet known, as in SCCRQ).
    Bytes 8-9 / 10-11: Ns / Nr sequence numbers.
    """
    body = b"".join(avps)
    length = 12 + len(body)
    header = struct.pack("!BBHIHH", 0xC8, 0x03, length, recipient_ccid, ns, nr)
    return outer(a_to_b, header + body)


def data(a_to_b, session_id, frame):
    """Build an L2TPv3-over-UDP data message (RFC 3931 section 4.1.2.1).

    Byte 0: flags, T(ype) bit 0 => data message, all other flags clear.
    Byte 1: low nibble is Version = 3 (high nibble reserved, 0).
    Bytes 2-3: Reserved (0).
    Bytes 4-7: Session ID. No optional Cookie and no L2-Specific Sublayer, so
    the Ethernet pseudowire frame follows immediately.
    """
    header = struct.pack("!BBHI", 0x00, 0x03, 0x0000, session_id)
    return outer(a_to_b, header + bytes(frame))


def session_avps(msg_type, local_sid, remote_sid):
    """AVPs that establish/identify an Ethernet pseudowire session."""
    return [
        message_type_avp(msg_type),
        avp(AVP_LOCAL_SESSION_ID, struct.pack("!I", local_sid)),
        avp(AVP_REMOTE_SESSION_ID, struct.pack("!I", remote_sid)),
        avp(AVP_PW_TYPE, struct.pack("!H", PW_TYPE_ETHERNET)),
        avp(AVP_L2_SPECIFIC_SUBLAYER, struct.pack("!H", 0)),
        avp(AVP_DATA_SEQUENCING, struct.pack("!H", 0)),
        avp(AVP_CIRCUIT_STATUS, struct.pack("!H", CIRCUIT_STATUS_ACTIVE_NEW)),
    ]


def control_packets_setup():
    """Control-connection and session establishment (A initiates)."""
    return [
        # Control connection: advertise an Ethernet pseudowire capability.
        control(
            True,
            0,
            0,
            0,
            [
                message_type_avp(SCCRQ),
                avp(AVP_ASSIGNED_CCID, struct.pack("!I", CCID_A)),
                avp(AVP_PW_CAPABILITIES, struct.pack("!H", PW_TYPE_ETHERNET)),
            ],
        ),
        control(
            False,
            CCID_A,
            0,
            1,
            [
                message_type_avp(SCCRP),
                avp(AVP_ASSIGNED_CCID, struct.pack("!I", CCID_B)),
                avp(AVP_PW_CAPABILITIES, struct.pack("!H", PW_TYPE_ETHERNET)),
            ],
        ),
        control(True, CCID_B, 1, 1, [message_type_avp(SCCCN)]),
        # Session: each side advertises its Local Session ID + Ethernet pw type.
        control(True, CCID_B, 2, 1, session_avps(ICRQ, SESSION_B_TO_A, 0)),
        control(
            False, CCID_A, 1, 3, session_avps(ICRP, SESSION_A_TO_B, SESSION_B_TO_A)
        ),
        control(
            True,
            CCID_B,
            3,
            2,
            [
                message_type_avp(ICCN),
                avp(AVP_LOCAL_SESSION_ID, struct.pack("!I", SESSION_B_TO_A)),
                avp(AVP_REMOTE_SESSION_ID, struct.pack("!I", SESSION_A_TO_B)),
            ],
        ),
    ]


def control_packets_teardown():
    """Session and control-connection teardown (A initiates)."""
    return [
        control(
            True,
            CCID_B,
            4,
            2,
            [
                message_type_avp(CDN),
                avp(AVP_RESULT_CODE, struct.pack("!H", 3)),  # administrative
                avp(AVP_LOCAL_SESSION_ID, struct.pack("!I", SESSION_B_TO_A)),
                avp(AVP_REMOTE_SESSION_ID, struct.pack("!I", SESSION_A_TO_B)),
            ],
        ),
        control(
            True,
            CCID_B,
            5,
            2,
            [
                message_type_avp(STOPCCN),
                avp(AVP_RESULT_CODE, struct.pack("!H", 1)),  # general request
                avp(AVP_ASSIGNED_CCID, struct.pack("!I", CCID_A)),
            ],
        ),
    ]


def inner_frame(is_c2s, seq, ack, flags, payload=b""):
    """A tunneled inner Ethernet frame carrying one TCP segment."""
    if is_c2s:
        eth_src, eth_dst = INNER_CLIENT_MAC, INNER_SERVER_MAC
        ip_src, ip_dst = INNER_CLIENT, INNER_SERVER
        sport, dport = INNER_CLIENT_PORT, INNER_SERVER_PORT
    else:
        eth_src, eth_dst = INNER_SERVER_MAC, INNER_CLIENT_MAC
        ip_src, ip_dst = INNER_SERVER, INNER_CLIENT
        sport, dport = INNER_SERVER_PORT, INNER_CLIENT_PORT

    frame = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=ip_src, dst=ip_dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        frame = frame / Raw(payload)
    return frame


def tunnel(is_c2s, frame):
    """Wrap an inner frame in an L2TPv3 data message inside a UDP datagram."""
    if is_c2s:
        return data(True, SESSION_A_TO_B, frame)
    return data(False, SESSION_B_TO_A, frame)


def data_packets():
    """The tunneled inner TCP/HTTP flow, one inner frame per data message."""
    c_isn = 1000
    s_isn = 5000
    req_len = len(HTTP_REQUEST)
    resp_len = len(HTTP_RESPONSE)

    inner = [
        # Handshake.
        (True, inner_frame(True, c_isn, 0, "S")),
        (False, inner_frame(False, s_isn, c_isn + 1, "SA")),
        (True, inner_frame(True, c_isn + 1, s_isn + 1, "A")),
        # HTTP GET to whatsmyip.com and its ack.
        (True, inner_frame(True, c_isn + 1, s_isn + 1, "PA", HTTP_REQUEST)),
        (False, inner_frame(False, s_isn + 1, c_isn + 1 + req_len, "A")),
        # HTTP 200 OK response and its ack.
        (
            False,
            inner_frame(False, s_isn + 1, c_isn + 1 + req_len, "PA", HTTP_RESPONSE),
        ),
        (True, inner_frame(True, c_isn + 1 + req_len, s_isn + 1 + resp_len, "A")),
        # Teardown (server closes: "Connection: close"). A FIN consumes one seq.
        (False, inner_frame(False, s_isn + 1 + resp_len, c_isn + 1 + req_len, "FA")),
        (True, inner_frame(True, c_isn + 1 + req_len, s_isn + 2 + resp_len, "FA")),
        (False, inner_frame(False, s_isn + 2 + resp_len, c_isn + 2 + req_len, "A")),
    ]

    return [tunnel(is_c2s, frame) for is_c2s, frame in inner]


def build_packets():
    return control_packets_setup() + data_packets() + control_packets_teardown()


def main():
    packets = build_packets()

    # Deterministic, monotonically increasing timestamps.
    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
