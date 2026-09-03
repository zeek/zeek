#!/usr/bin/env python3
"""Generate ldap-abandon.pcap -- an LDAP abandon that Zeek fails to parse.

One TCP connection, client 10.10.10.50:47122 -> server 10.10.10.10:389, plain
LDAP (no TLS, no SASL), with a full three-way handshake and FIN/ACK teardown.

LDAP messages, in order:
  1 -> bindRequest, simple auth as cn=admin,dc=example,dc=com
  1 <- bindResponse, success
  2 -> searchRequest, base dc=example,dc=com, filter (objectClass=*)
  2 <- searchResEntry for uid=jdoe,ou=People,dc=example,dc=com
  3 -> abandonRequest, abandoning message 2
  4 -> searchRequest, base dc=example,dc=com, filter (objectClass=*)
  4 <- searchResDone, success
  5 -> unbindRequest

The abandonRequest is encoded per RFC 4511: AbandonRequest ::= [APPLICATION 16]
MessageID is IMPLICIT-tagged, so the protocolOp is the primitive tag 0x50 followed
directly by the integer octets (0x50 0x01 0x02), with no nested INTEGER TLV.

The second search and the unbind are there on purpose: Zeek's violation on the
abandon disables LDAP_TCP for the whole connection, so neither of them is logged.

Ethernet/IP/TCP framing and the pcap file are produced with high-level Scapy
primitives (Ether/IP/TCP/wrpcap). The LDAP protocolOps are still assembled from
small BER helpers because Scapy's LDAP layer offers no representation for the
IMPLICIT-tagged, primitive AbandonRequest this trace exists to exercise.

Generated with Claude Opus 5 (model claude-opus-5) via Claude Code; rewritten to
use high-level Scapy primitives with Claude Opus 4.8 (model claude-opus-4-8).
"""

import argparse

from scapy.all import IP, TCP, Ether, wrpcap

# --- BER -------------------------------------------------------------------


def ber_len(n):
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def tlv(tag, content):
    return bytes([tag]) + ber_len(len(content)) + content


def integer(value):
    return tlv(0x02, int_content(value))


def int_content(value):
    """Bare INTEGER content octets, without the universal tag and length.

    Used for IMPLICIT-tagged INTEGERs such as AbandonRequest's MessageID.
    """
    if value == 0:
        return b"\x00"
    out = b""
    n = value
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    if out[0] & 0x80:
        out = b"\x00" + out
    return out


def enumerated(value):
    return tlv(0x0A, bytes([value]))


def octet_string(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return tlv(0x04, value)


def boolean(value):
    return tlv(0x01, b"\xff" if value else b"\x00")


def sequence(*items):
    return tlv(0x30, b"".join(items))


def set_of(*items):
    return tlv(0x31, b"".join(items))


# --- LDAP (RFC 4511) -------------------------------------------------------

APP_BIND_REQUEST = 0x60  # [APPLICATION 0]  SEQUENCE, constructed
APP_BIND_RESPONSE = 0x61  # [APPLICATION 1]  SEQUENCE, constructed
APP_UNBIND_REQUEST = 0x42  # [APPLICATION 2]  NULL, primitive, no content
APP_SEARCH_REQUEST = 0x63  # [APPLICATION 3]  SEQUENCE, constructed
APP_SEARCH_RES_ENTRY = 0x64  # [APPLICATION 4]  SEQUENCE, constructed
APP_SEARCH_RES_DONE = 0x65  # [APPLICATION 5]  SEQUENCE, constructed
APP_ABANDON_REQUEST = 0x50  # [APPLICATION 16] MessageID, primitive (!)


def ldap_message(message_id, protocol_op):
    return sequence(integer(message_id), protocol_op)


def bind_request(message_id, name, password):
    body = integer(3) + octet_string(name) + tlv(0x80, password.encode("utf-8"))
    return ldap_message(message_id, tlv(APP_BIND_REQUEST, body))


def _result(code=0, matched_dn="", diagnostic=""):
    return enumerated(code) + octet_string(matched_dn) + octet_string(diagnostic)


def bind_response(message_id, code=0):
    return ldap_message(message_id, tlv(APP_BIND_RESPONSE, _result(code)))


def unbind_request(message_id):
    return ldap_message(message_id, tlv(APP_UNBIND_REQUEST, b""))


def search_request(message_id, base, attr="objectClass"):
    body = (
        octet_string(base)
        + enumerated(2)  # scope: wholeSubtree
        + enumerated(0)  # derefAliases: neverDerefAliases
        + integer(0)  # sizeLimit
        + integer(0)  # timeLimit
        + boolean(False)  # typesOnly
        + tlv(0x87, attr.encode("utf-8"))  # filter: present, [CONTEXT 7]
        + sequence()  # AttributeSelection: empty
    )
    return ldap_message(message_id, tlv(APP_SEARCH_REQUEST, body))


def search_result_entry(message_id, dn, attr_type, attr_value):
    body = octet_string(dn) + sequence(
        sequence(octet_string(attr_type), set_of(octet_string(attr_value)))
    )
    return ldap_message(message_id, tlv(APP_SEARCH_RES_ENTRY, body))


def search_result_done(message_id, code=0):
    return ldap_message(message_id, tlv(APP_SEARCH_RES_DONE, _result(code)))


def abandon_request(message_id, abandon_id):
    # AbandonRequest ::= [APPLICATION 16] MessageID -- IMPLICIT tag over an
    # INTEGER, so the content octets are the integer itself, not a nested TLV.
    return ldap_message(message_id, tlv(APP_ABANDON_REQUEST, int_content(abandon_id)))


# --- TCP session -----------------------------------------------------------

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_IP = "10.10.10.50"
SERVER_IP = "10.10.10.10"
CLIENT_PORT = 47122
SERVER_PORT = 389


class Session:
    """A single client/server TCP session collected as Scapy packets."""

    def __init__(self, start_ts=1755000000.0):
        self.packets = []
        self.ts = start_ts
        self.c_seq = 1000
        self.s_seq = 5000

    def _send(self, from_client, flags, payload=b""):
        if from_client:
            eth = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            ip = IP(src=CLIENT_IP, dst=SERVER_IP)
            tcp = TCP(
                sport=CLIENT_PORT,
                dport=SERVER_PORT,
                flags=flags,
                seq=self.c_seq,
                ack=self.s_seq,
            )
        else:
            eth = Ether(src=SERVER_MAC, dst=CLIENT_MAC)
            ip = IP(src=SERVER_IP, dst=CLIENT_IP)
            tcp = TCP(
                sport=SERVER_PORT,
                dport=CLIENT_PORT,
                flags=flags,
                seq=self.s_seq,
                ack=self.c_seq,
            )

        pkt = eth / ip / tcp
        if payload:
            pkt = pkt / payload
        self.ts += 0.000250
        pkt.time = self.ts
        self.packets.append(pkt)

        consumed = len(payload) + (1 if "S" in tcp.flags or "F" in tcp.flags else 0)
        if from_client:
            self.c_seq += consumed
        else:
            self.s_seq += consumed

    def handshake(self):
        self._send(True, "S")
        self._send(False, "SA")
        self._send(True, "A")

    def client_data(self, payload):
        self._send(True, "PA", payload)
        self._send(False, "A")

    def server_data(self, payload):
        self._send(False, "PA", payload)
        self._send(True, "A")

    def teardown(self):
        self._send(True, "FA")
        self._send(False, "A")
        self._send(False, "FA")
        self._send(True, "A")

    def write(self, path):
        wrpcap(path, self.packets)


# --- Trace -----------------------------------------------------------------

BIND_DN = "cn=admin,dc=example,dc=com"
BIND_PW = "Passw0rd!"
BASE_DN = "dc=example,dc=com"
TARGET_DN = "uid=jdoe,ou=People,dc=example,dc=com"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o", "--output", default="ldap-abandon.pcap", help="output pcap path"
    )
    args = parser.parse_args()

    s = Session()
    s.handshake()
    s.client_data(bind_request(1, BIND_DN, BIND_PW))
    s.server_data(bind_response(1))
    s.client_data(search_request(2, BASE_DN))
    s.server_data(search_result_entry(2, TARGET_DN, "objectClass", "inetOrgPerson"))
    s.client_data(abandon_request(3, 2))
    # Everything below happens after the abandon, on the same connection.
    s.client_data(search_request(4, BASE_DN))
    s.server_data(search_result_done(4))
    s.client_data(unbind_request(5))
    s.teardown()
    s.write(args.output)


if __name__ == "__main__":
    main()
