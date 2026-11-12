#!/usr/bin/env python3
"""Generate a DNP3/TCP trace that exercises the pseudo-transport FIR and sequence rules (no dependencies).

    python3 dnp3-transport-rules.pcap.py [OUT]   # default: dnp3-transport-rules.pcap next to this script

Five connections from a master at 10.0.0.1 (address 1) to an outstation at 10.0.0.2:20000
(address 10). Every link frame is well formed; only the transport octet is unusual. Each
connection carries READs of group 30 variation 1 (start = stop = the READ's number). The
outstation answers each READ it accepts with an empty RESPONSE; READs that an outstation
discards by the transport rules (IEEE 1815, 8.2) get no answer.

  port 40001  READ 1 starts a fragment (FIR, no FIN) with only its first two octets, then
              READ 2 arrives whole (FIR and FIN): READ 1 is dropped, READ 2 is accepted
  port 40002  a segment with FIR and FIN and no application octets before READ 1
  port 40003  READ 1 in two segments whose sequence numbers are not consecutive: dropped
  port 40004  READ 1 in a segment without FIR when no fragment is in progress: dropped
  port 40005  READ 1 in two segments with consecutive sequence numbers (accepted), for reference

In every connection, READ 0 comes first and READs 2 to 4 follow, whole and valid.

Written with the assistance of Claude (Anthropic, model claude-opus-5-5), reviewed by the author.
"""

import os
import struct
import sys


def crc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if c & 1 else c >> 1
    return ~c & 0xFFFF


def frame(ctl, dst, src, user):
    h = bytes(
        [0x05, 0x64, 5 + len(user), ctl, dst & 0xFF, dst >> 8, src & 0xFF, src >> 8]
    )
    out = bytearray(h + crc(h).to_bytes(2, "little"))
    for i in range(0, len(user), 16):
        b = bytes(user[i : i + 16])
        out += b + crc(b).to_bytes(2, "little")
    return bytes(out)


OUTSTATION, MASTER = 10, 1


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


class Conn:
    """One TCP connection."""

    def __init__(self, pkts, port):
        self.pkts, self.port = pkts, port
        self.m, self.o = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
        self.ms, self.os = 1000, 5000
        self.tseq_m = self.tseq_o = self.aseq = 0
        self.add(self.m, self.o, self.port, 20000, self.ms, 0, 0x02)
        self.add(self.o, self.m, 20000, self.port, self.os, self.ms + 1, 0x12)
        self.ms, self.os = self.ms + 1, self.os + 1
        self.add(self.m, self.o, self.port, 20000, self.ms, self.os, 0x10)

    def add(self, *args):
        self.pkts.append(packet(*args))

    def client(self, data):
        self.add(self.m, self.o, self.port, 20000, self.ms, self.os, 0x18, data)
        self.ms += len(data)

    def server(self, data):
        self.add(self.o, self.m, 20000, self.port, self.os, self.ms, 0x18, data)
        self.os += len(data)

    def tp(self, fir=True, fin=True, skip=0):
        x = (0x40 if fir else 0) | (0x80 if fin else 0) | self.tseq_m
        self.tseq_m = (self.tseq_m + 1 + skip) & 0x3F
        return bytes([x])

    def send(self, user, answered):
        self.client(frame(0xC4, OUTSTATION, MASTER, user))
        if answered:
            self.response()

    def request(self, app):
        self.send(self.tp() + bytes([0xC0 | self.aseq]) + app, True)

    def response(self):
        user = bytes([0xC0 | self.tseq_o, 0xC0 | self.aseq, 0x81, 0x00, 0x00])
        self.tseq_o = (self.tseq_o + 1) & 0x3F
        self.aseq = (self.aseq + 1) & 0x0F
        self.server(frame(0x44, MASTER, OUTSTATION, user))

    def finish(self):
        self.add(self.m, self.o, self.port, 20000, self.ms, self.os, 0x11)
        self.add(self.o, self.m, 20000, self.port, self.os, self.ms + 1, 0x11)
        self.add(self.m, self.o, self.port, 20000, self.ms + 1, self.os + 1, 0x10)


def read(n):
    # READ, group 30 variation 1, qualifier 0x00 (1-octet start and stop), start = stop = n
    return bytes([0x01, 30, 1, 0x00, n, n])


def case(c, port):
    a = bytes([0xC0 | c.aseq]) + read(1)
    if port == 40001:
        c.send(c.tp(fin=False) + a[:2], False)
        c.request(read(2))
        return
    if port == 40002:
        c.send(c.tp(), False)
        c.request(read(1))
    elif port == 40003:
        c.send(c.tp(fin=False, skip=1) + a[:3], False)
        c.send(c.tp(fir=False) + a[3:], False)
    elif port == 40004:
        c.send(c.tp(fir=False) + a, False)
    elif port == 40005:
        c.send(c.tp(fin=False) + a[:3], False)
        c.send(c.tp(fir=False) + a[3:], True)
    c.request(read(2))


def main():
    out = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "dnp3-transport-rules.pcap"
        )
    )
    pkts = []
    for port in (40001, 40002, 40003, 40004, 40005):
        c = Conn(pkts, port)
        c.request(read(0))
        case(c, port)
        for n in (3, 4):
            c.request(read(n))
        c.finish()
    with open(out, "wb") as f:
        f.write(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 0)
        )  # LINKTYPE_NULL
        for i, p in enumerate(pkts):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)) + p)


if __name__ == "__main__":
    main()
