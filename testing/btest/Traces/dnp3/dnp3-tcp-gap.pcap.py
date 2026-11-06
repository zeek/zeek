#!/usr/bin/env python3
"""Generate a DNP3/TCP trace in which each connection loses one TCP segment (no dependencies).

    python3 dnp3-tcp-gap.pcap.py [OUT]   # default: dnp3-tcp-gap.pcap next to this script

Four connections from a master at 10.0.0.1 (address 1) to an outstation at 10.0.0.2:20000
(address 10). On each, the master sends 10 READs of group 30 variation 1 (qualifier 0x00,
start = stop = the READ's number, 0 to 9) and the outstation answers each with an empty
RESPONSE. Every frame is well formed. One client-to-server segment is missing from each
connection, so the analyzer sees a TCP gap:

  port 40001  every frame in two segments (10 octets, then the rest); the second half of
              READ 4 is lost, so the data after the gap starts at the next frame
  port 40002  the same split; the first half of READ 4 is lost, so the data after the gap
              starts in the middle of a frame
  port 40003  after READ 4 the master sends a WRITE of three 200-octet strings (group 110
              variation 200): one application fragment in three link frames, one per
              segment, answered with an empty RESPONSE; its first frame is lost
  port 40004  the same WRITE; the second half of its middle frame is lost

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
    """One TCP connection. A lost segment advances the sequence number but is not written."""

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

    def client(self, data, lost=False):
        if not lost:
            self.add(self.m, self.o, self.port, 20000, self.ms, self.os, 0x18, data)
        self.ms += len(data)

    def server(self, data):
        self.add(self.o, self.m, 20000, self.port, self.os, self.ms, 0x18, data)
        self.os += len(data)

    def request(self, app, split=False, lost=None):
        # transport FIR|FIN and application control FIR|FIN, then the application data
        user = bytes([0xC0 | self.tseq_m, 0xC0 | self.aseq]) + app
        self.tseq_m = (self.tseq_m + 1) & 0x3F
        f = frame(0xC4, OUTSTATION, MASTER, user)
        if split:
            self.client(f[:10], lost == "head")
            self.client(f[10:], lost == "tail")
        else:
            self.client(f)
        self.response()

    def response(self):
        user = bytes([0xC0 | self.tseq_o, 0xC0 | self.aseq, 0x81, 0x00, 0x00])
        self.tseq_o = (self.tseq_o + 1) & 0x3F
        self.aseq = (self.aseq + 1) & 0x0F
        self.server(frame(0x44, MASTER, OUTSTATION, user))

    def write(self, lost):
        app = (
            bytes([0xC0 | self.aseq, 0x02, 110, 200, 0x00, 0, 2])
            + bytes(range(200)) * 3
        )
        chunks = [app[k : k + 249] for k in range(0, len(app), 249)]
        for j, ch in enumerate(chunks):
            th = (
                self.tseq_m
                | (0x40 if j == 0 else 0)
                | (0x80 if j == len(chunks) - 1 else 0)
            )
            self.tseq_m = (self.tseq_m + 1) & 0x3F
            f = frame(0xC4, OUTSTATION, MASTER, bytes([th]) + ch)
            if lost == "first" and j == 0:
                self.client(f, lost=True)
            elif lost == "middle-half" and j == 1:
                self.client(f[:100])
                self.client(f[100:], lost=True)
            else:
                self.client(f)
        self.response()

    def finish(self):
        self.add(self.m, self.o, self.port, 20000, self.ms, self.os, 0x11)
        self.add(self.o, self.m, 20000, self.port, self.os, self.ms + 1, 0x11)
        self.add(self.m, self.o, self.port, 20000, self.ms + 1, self.os + 1, 0x10)


def read(n):
    # READ, group 30 variation 1, qualifier 0x00 (1-octet start and stop), start = stop = n
    return bytes([0x01, 30, 1, 0x00, n, n])


def main():
    out = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "dnp3-tcp-gap.pcap"
        )
    )
    pkts = []
    for port, lost in ((40001, "tail"), (40002, "head")):
        c = Conn(pkts, port)
        for n in range(10):
            c.request(read(n), split=True, lost=lost if n == 4 else None)
        c.finish()
    for port, lost in ((40003, "first"), (40004, "middle-half")):
        c = Conn(pkts, port)
        for n in range(10):
            c.request(read(n))
            if n == 4:
                c.write(lost)
        c.finish()
    with open(out, "wb") as f:
        f.write(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 0)
        )  # LINKTYPE_NULL
        for i, p in enumerate(pkts):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)) + p)


if __name__ == "__main__":
    main()
