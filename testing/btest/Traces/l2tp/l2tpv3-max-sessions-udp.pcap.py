#!/usr/bin/env python3
"""Exercises the L2TPv3 maximum-session-count limit over UDP.

Builds a UDP-encapsulated L2TPv3 (RFC 3931) tunnel between two LCCEs on port
1701 and then opens several Ethernet-pseudowire sessions in a row so the
analyzer's per-tunnel session map grows past its configured maximum:

  * Control plane: one control-connection setup (SCCRQ / SCCRP / SCCCN), then a
    run of N session setups (ICRQ / ICRP / ICCN), each advertising a distinct
    pair of Local / Remote Session IDs. The ICRP is the message that makes the
    analyzer insert per-direction session state, so each accepted ICRP adds two
    entries to the session map. Once the map is already larger than
    L2TP::v3_max_sessions, the analyzer emits a weird and drops the offending
    ICRP instead of inserting its state.
  * Data plane: after setup, one inner TCP SYN is tunnelled for a session that
    was accepted (its Session ID resolves, so the inner frame decodes into a
    connection) and one for a session whose ICRP was dropped by the limit (its
    Session ID does not resolve, so the inner frame is dropped and no connection
    appears). This is what shows the limit actually suppressed the state rather
    than only logging.

The number of sessions here is sized so that, with a small
L2TP::v3_max_sessions redef in the accompanying btest, some sessions are
accepted and at least one is rejected. The default limit (4000) would need
thousands of sessions, so the btest lowers it rather than this script emitting a
huge trace.

Scapy's scapy.layers.l2tp.L2TP only models L2TPv2 (16-bit tunnel/session IDs),
so the L2TPv3-over-UDP control and data headers and the control-message AVPs are
written as documented fixed blobs; the outer carrier and the entire inner frame
use Scapy's high-level API (which computes all lengths and checksums).

Generates an L2TPv3-over-UDP trace that drives the V3 session-count limit.
Written with claude-opus-4-8 using Scapy (disclose AI assistance per
AI_POLICY.md).
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

# Number of pseudowire sessions to set up. With the btest redef'ing
# L2TP::v3_max_sessions to 2, the first sessions are accepted and the later
# one(s) are rejected once the map has grown past the limit.
NUM_SESSIONS = 3


# Per-session, per-direction Session IDs (nonzero; 0 is reserved for control).
# Session i (1-based) gets a distinct pair. The Session ID in a data message is
# the one assigned by the *receiver*: a data message A->B carries B's Local
# Session ID (advertised in that session's ICRP).
def session_a_to_b(i):
    return 0x1A2B0000 + i  # B's Local Session ID for session i


def session_b_to_a(i):
    return 0x4D3C0000 + i  # A's Local Session ID for session i


# Inner Ethernet pseudowire endpoints.
INNER_CLIENT = "10.1.1.100"
INNER_SERVER = "203.0.113.50"
INNER_CLIENT_MAC = "02:aa:aa:aa:aa:aa"
INNER_SERVER_MAC = "02:bb:bb:bb:bb:bb"
INNER_CLIENT_PORT = 49152
INNER_SERVER_PORT = 80

BASE_TIME = 1_700_000_000.0

# L2TPv3 control message types (RFC 3931).
SCCRQ, SCCRP, SCCCN, STOPCCN = 1, 2, 3, 4
ICRQ, ICRP, ICCN, CDN = 10, 11, 12, 14
HELLO = 6

# L2TPv3 control message AVP attribute types (RFC 3931).
AVP_MESSAGE_TYPE = 0
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

    Byte 0: flags, T=1 (control) | L=1 (length present) | S=1 (sequence present)
    => 0xC8, all other flags clear.
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
    Bytes 4-7: Session ID. No optional Cookie and no L2-Specific Sublayer, so the
    Ethernet pseudowire frame follows immediately.
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


def control_connection_setup():
    """Control-connection establishment (A initiates), shared by all sessions."""
    return [
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
    ]


def session_setup(i, ns_a, ns_b):
    """ICRQ / ICRP / ICCN for session i. The ICRP carries both Session IDs and
    is what makes the analyzer insert (or, once over the limit, reject) the
    per-direction session state. ns_a / ns_b are the next A->B / B->A control
    sequence numbers; returns (packets, next_ns_a, next_ns_b)."""
    a2b = session_a_to_b(i)
    b2a = session_b_to_a(i)
    packets = [
        control(True, CCID_B, ns_a, 1, session_avps(ICRQ, b2a, 0)),
        control(False, CCID_A, ns_b, ns_a + 1, session_avps(ICRP, a2b, b2a)),
        control(
            True,
            CCID_B,
            ns_a + 1,
            ns_b + 1,
            [
                message_type_avp(ICCN),
                avp(AVP_LOCAL_SESSION_ID, struct.pack("!I", b2a)),
                avp(AVP_REMOTE_SESSION_ID, struct.pack("!I", a2b)),
            ],
        ),
    ]
    return packets, ns_a + 2, ns_b + 1


def inner_syn(sport):
    """A tunneled inner Ethernet frame carrying a single client->server TCP SYN."""
    return (
        Ether(src=INNER_CLIENT_MAC, dst=INNER_SERVER_MAC)
        / IP(src=INNER_CLIENT, dst=INNER_SERVER)
        / TCP(sport=sport, dport=INNER_SERVER_PORT, seq=1000, flags="S")
    )


def build_packets():
    packets = list(control_connection_setup())

    ns_a, ns_b = 2, 1
    for i in range(1, NUM_SESSIONS + 1):
        session_pkts, ns_a, ns_b = session_setup(i, ns_a, ns_b)
        packets.extend(session_pkts)

    # Data for an accepted session (session 1) decodes into an inner connection;
    # data for the last session (rejected once the map is over the limit) does
    # not resolve and is dropped, so it produces no inner connection. Distinct
    # inner source ports keep the two probes separable in conn.log.
    packets.append(data(True, session_a_to_b(1), inner_syn(49152)))
    packets.append(data(True, session_a_to_b(NUM_SESSIONS), inner_syn(49153)))

    return packets


def main():
    packets = build_packets()

    # Deterministic, monotonically increasing timestamps.
    for index, pkt in enumerate(packets):
        pkt.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
