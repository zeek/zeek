#!/usr/bin/env python3
"""Generate an RDP trace in which one Connection Request has a TPKT version other than 3 (no dependencies).

    python3 rdp-tpkt-version.pcap.py [OUT]   # default: rdp-tpkt-version.pcap next to this script

Two connections from 10.0.0.1 to an RDP server at 10.0.0.2:3389. Each sends one X.224 Connection Request with the
cookie "mstshash=<name>" and an RDP Negotiation Request.

  port 40001  TPKT version 3; the server answers with a Connection Confirm
  port 40002  the same request with TPKT version 4 (RFC 1006 defines only version 3); the server sends nothing and
              closes, as xrdp and FreeRDP do

Written with the assistance of Claude (Anthropic, model claude-opus-5-5), reviewed by the author.
"""

import os
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def packet(src, dst, sport, dport, seq, ack, flags, payload=b""):
    tcp = (
        struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
        + payload
    )
    pseudo = struct.pack("!4s4sBBH", src, dst, 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0, src, dst
    )
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return b"\x02\x00\x00\x00" + ip + tcp  # DLT_NULL, AF_INET


def tpkt(payload, version=3):
    return bytes([version, 0]) + struct.pack(">H", len(payload) + 4) + payload


def connection_request(cookie, version=3):
    ud = f"Cookie: mstshash={cookie}\r\n".encode() + bytes([1, 0, 8, 0, 0, 0, 0, 0])
    return tpkt(bytes([6 + len(ud), 0xE0, 0, 0, 0, 0, 0]) + ud, version)


def connection_confirm():
    return tpkt(bytes([14, 0xD0, 0, 0, 0x12, 0x34, 0, 2, 0, 8, 0, 0, 0, 0, 0]))


def connection(pkts, port, version):
    c, s = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
    cs, ss = 1000, 5000
    pkts.append(packet(c, s, port, 3389, cs, 0, 0x02))
    pkts.append(packet(s, c, 3389, port, ss, cs + 1, 0x12))
    cs, ss = cs + 1, ss + 1
    pkts.append(packet(c, s, port, 3389, cs, ss, 0x10))
    req = connection_request(f"user{port}", version)
    pkts.append(packet(c, s, port, 3389, cs, ss, 0x18, req))
    cs += len(req)
    if version == 3:
        cc = connection_confirm()
        pkts.append(packet(s, c, 3389, port, ss, cs, 0x18, cc))
        ss += len(cc)
    pkts.append(packet(s, c, 3389, port, ss, cs, 0x11))
    pkts.append(packet(c, s, port, 3389, cs, ss + 1, 0x11))
    pkts.append(packet(s, c, 3389, port, ss + 1, cs + 1, 0x10))


def main():
    out = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "rdp-tpkt-version.pcap"
        )
    )
    pkts = []
    connection(pkts, 40001, 3)
    connection(pkts, 40002, 4)
    with open(out, "wb") as f:
        f.write(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 0)
        )  # LINKTYPE_NULL
        for i, p in enumerate(pkts):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)) + p)


if __name__ == "__main__":
    main()
