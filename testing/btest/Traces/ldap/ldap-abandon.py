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

Generated with Claude Opus 5 (model claude-opus-5) via Claude Code.
"""

import os
import struct
import sys

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


# --- Ethernet / IPv4 / TCP / pcap ------------------------------------------

CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
CLIENT_IP = "10.10.10.50"
SERVER_IP = "10.10.10.10"
CLIENT_PORT = 47122
SERVER_PORT = 389

FIN = 0x01
SYN = 0x02
PSH = 0x08
ACK = 0x10


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(src, dst, payload, ident):
    src_b = bytes(int(x) for x in src.split("."))
    dst_b = bytes(int(x) for x in dst.split("."))
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        ident,
        0x4000,
        64,
        6,
        0,
        src_b,
        dst_b,
    )
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
    src_b = bytes(int(x) for x in src_ip.split("."))
    dst_b = bytes(int(x) for x in dst_ip.split("."))
    pseudo = struct.pack("!4s4sBBH", src_b, dst_b, 0, 6, len(header) + len(payload))
    csum = checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", csum) + header[18:] + payload


def ethernet(src_mac, dst_mac, payload):
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + payload


class Session:
    """A single client/server TCP session written into a pcap file."""

    def __init__(self, path, start_ts=1755000000.0):
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        self.ts = start_ts
        self.ident = 1
        self.c_seq = 1000
        self.s_seq = 5000

    def _write(self, frame):
        self.ts += 0.000250
        sec = int(self.ts)
        usec = int(round((self.ts - sec) * 1_000_000))
        self.fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        self.fh.write(frame)

    def _send(self, from_client, flags, payload=b""):
        if from_client:
            src_ip, dst_ip = CLIENT_IP, SERVER_IP
            src_mac, dst_mac = CLIENT_MAC, SERVER_MAC
            sport, dport = CLIENT_PORT, SERVER_PORT
            seq, ack = self.c_seq, self.s_seq
        else:
            src_ip, dst_ip = SERVER_IP, CLIENT_IP
            src_mac, dst_mac = SERVER_MAC, CLIENT_MAC
            sport, dport = SERVER_PORT, CLIENT_PORT
            seq, ack = self.s_seq, self.c_seq

        self.ident += 1
        segment = tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, payload)
        self._write(
            ethernet(src_mac, dst_mac, ipv4(src_ip, dst_ip, segment, self.ident))
        )

        consumed = len(payload) + (1 if flags & (SYN | FIN) else 0)
        if from_client:
            self.c_seq += consumed
        else:
            self.s_seq += consumed

    def handshake(self):
        self._send(True, SYN)
        self._send(False, SYN | ACK)
        self._send(True, ACK)

    def client_data(self, payload):
        self._send(True, PSH | ACK, payload)
        self._send(False, ACK)

    def server_data(self, payload):
        self._send(False, PSH | ACK, payload)
        self._send(True, ACK)

    def teardown(self):
        self._send(True, FIN | ACK)
        self._send(False, ACK)
        self._send(False, FIN | ACK)
        self._send(True, ACK)

    def close(self):
        self.fh.close()


# --- Trace -----------------------------------------------------------------

BIND_DN = "cn=admin,dc=example,dc=com"
BIND_PW = "Passw0rd!"
BASE_DN = "dc=example,dc=com"
TARGET_DN = "uid=jdoe,ou=People,dc=example,dc=com"


def main():
    path = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "ldap-abandon.pcap"
        )
    )

    s = Session(path)
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
    s.close()


if __name__ == "__main__":
    main()
