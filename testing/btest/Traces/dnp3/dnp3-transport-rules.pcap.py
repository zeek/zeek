#!/usr/bin/env python3
"""Generate a DNP3/TCP trace that exercises the pseudo-transport rules (no dependencies).

    python3 dnp3-transport-rules.pcap.py [OUT]   # default: dnp3-transport-rules.pcap next to this script

Connections from a master at 10.0.0.1 (address 1) to an outstation at 10.0.0.2:20000
(address 10). Each one carries READs of group 30 variation 1 with start = stop = n
("READ n"). READ 0 comes first and READs 3 and 4 follow, whole and valid, as controls.
The outstation answers each READ it accepts; the case in between is:

  port 40001  READ 1 starts a fragment (FIR, no FIN) with only its first two octets,
              then READ 2 arrives whole: READ 1 is dropped, READ 2 is accepted
  port 40002  a lone segment with FIR and FIN and no application octets, then READ 1
  port 40003  READ 1 in two segments whose sequence numbers are not consecutive: the
              second is ignored, and READ 2 then restarts the fragment
  port 40004  READ 1 in a segment without FIR when no fragment is in progress: dropped
  port 40005  READ 1 in two segments with consecutive sequence numbers (accepted)
  port 40006  READ 1 in a FIR segment without FIN, then an empty FIN segment (accepted)
  port 40007  READ 1 in two segments with an empty segment between them (accepted)
  port 40008  an empty FIR segment, then READ 1 in a FIN segment (accepted)
  port 40009  READ 1 in three segments, the middle one sent twice (accepted once)
  port 40010  READ 1 in two segments with a stray segment (sequence 9) between them
  port 40011  READ 1 in two segments with a FIR frame between them whose data CRC is
              corrupt (READ 9): that frame is dropped, READ 1 is accepted
  port 40012  READ 1 in two segments whose sequence numbers wrap from 63 to 0
  port 40013  READ 1 in two segments with a continuation from another link source
              address between them: it is ignored, READ 1 is accepted
  port 40014  a header with a valid CRC and LENGTH 4, then READ 1
  port 40015  READ 1 in two segments and the second TCP segment lost (a gap inside the
              fragment); READ 2 follows and must be parsed on its own
  port 40016  READ 1, answered by a response in two segments with the first one sent
              twice: the response's object header is decoded once
  port 40017  a READ of 16 objects in three segments of 33 octets: with the test's
              limit of 64 octets per fragment, the second segment exceeds it, the
              fragment and its last segment are dropped, and analysis continues

Written with the assistance of Claude (Anthropic, model claude-opus-5-5), reviewed by the author.
"""

import os
import sys

from scapy.all import IP, TCP, Ether, Raw, wrpcap


def crc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if c & 1 else c >> 1
    return ~c & 0xFFFF


def frame(ctl, dst, src, user, length=None, corrupt=False):
    h = bytes(
        [
            0x05,
            0x64,
            5 + len(user) if length is None else length,
            ctl,
            dst & 0xFF,
            dst >> 8,
            src & 0xFF,
            src >> 8,
        ]
    )
    out = bytearray(h + crc(h).to_bytes(2, "little"))
    for i in range(0, len(user), 16):
        b = bytes(user[i : i + 16])
        c = crc(b) ^ (0xFFFF if corrupt else 0)
        out += b + c.to_bytes(2, "little")
    return bytes(out)


OUTSTATION, MASTER = 10, 1
MAC = {"10.0.0.1": "02:00:00:00:00:01", "10.0.0.2": "02:00:00:00:00:02"}


def packet(src, dst, sport, dport, seq, ack, flags, payload=b""):
    p = (
        Ether(src=MAC[src], dst=MAC[dst])
        / IP(src=src, dst=dst, id=0, flags="DF", ttl=64)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=65535)
    )
    return p / Raw(payload) if payload else p


class Conn:
    """One TCP connection."""

    def __init__(self, pkts, port):
        self.pkts, self.port = pkts, port
        self.m, self.o = "10.0.0.1", "10.0.0.2"
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

    def tp(self, fir=True, fin=True, seq=None):
        if seq is None:
            seq = self.tseq_m
            self.tseq_m = (self.tseq_m + 1) & 0x3F
        return bytes([(0x40 if fir else 0) | (0x80 if fin else 0) | seq])

    def send(self, user, src=MASTER, **kw):
        self.client(frame(0xC4, OUTSTATION, src, user, **kw))

    def request(self, app):
        self.send(self.tp() + self.ac() + app)
        self.response()

    def ac(self):
        return bytes([0xC0 | self.aseq])

    def response(self, n=None, repeat_first=False):
        app = bytes([0xC0 | self.aseq, 0x81, 0x00, 0x00])
        if n is not None:
            # group 30 variation 1, start = stop = n: flags and a 32-bit value
            app += bytes([30, 1, 0x00, n, n, 0x01]) + n.to_bytes(4, "little")
        self.aseq = (self.aseq + 1) & 0x0F
        if not repeat_first:
            self.server(
                frame(0x44, MASTER, OUTSTATION, bytes([0xC0 | self.tseq_o]) + app)
            )
            self.tseq_o = (self.tseq_o + 1) & 0x3F
            return
        first = frame(0x44, MASTER, OUTSTATION, bytes([0x40 | self.tseq_o]) + app[:6])
        self.server(first)
        self.server(first)
        self.tseq_o = (self.tseq_o + 1) & 0x3F
        self.server(
            frame(0x44, MASTER, OUTSTATION, bytes([0x80 | self.tseq_o]) + app[6:])
        )
        self.tseq_o = (self.tseq_o + 1) & 0x3F

    def finish(self):
        self.add(self.m, self.o, self.port, 20000, self.ms, self.os, 0x11)
        self.add(self.o, self.m, 20000, self.port, self.os, self.ms + 1, 0x11)
        self.add(self.m, self.o, self.port, 20000, self.ms + 1, self.os + 1, 0x10)


def read(n):
    # READ, group 30 variation 1, qualifier 0x00 (1-octet start and stop), start = stop = n
    return bytes([0x01, 30, 1, 0x00, n, n])


def case(c, port):
    a = c.ac() + read(1)
    if port == 40001:
        c.send(c.tp(fin=False) + a[:2])
        c.request(read(2))
    elif port == 40002:
        c.send(c.tp())
        c.request(read(1))
    elif port == 40003:
        c.send(c.tp(fin=False) + a[:3])
        c.tseq_m = (c.tseq_m + 1) & 0x3F
        c.send(c.tp(fir=False) + a[3:])
        c.request(read(2))
    elif port == 40004:
        c.send(c.tp(fir=False) + a)
    elif port == 40005:
        c.send(c.tp(fin=False) + a[:3])
        c.send(c.tp(fir=False) + a[3:])
        c.response()
    elif port == 40006:
        c.send(c.tp(fin=False) + a)
        c.send(c.tp(fir=False))
        c.response()
    elif port == 40007:
        c.send(c.tp(fin=False) + a[:3])
        c.send(c.tp(fir=False, fin=False))
        c.send(c.tp(fir=False) + a[3:])
        c.response()
    elif port == 40008:
        c.send(c.tp(fin=False))
        c.send(c.tp(fir=False) + a)
        c.response()
    elif port == 40009:
        c.send(c.tp(fin=False) + a[:2])
        mid = c.tseq_m
        c.send(c.tp(fir=False, fin=False) + a[2:4])
        c.send(c.tp(fir=False, fin=False, seq=mid) + a[2:4])
        c.send(c.tp(fir=False) + a[4:])
        c.response()
    elif port == 40010:
        c.send(c.tp(fin=False) + a[:3])
        c.send(c.tp(fir=False, fin=False, seq=9) + a[3:])
        c.send(c.tp(fir=False) + a[3:])
        c.response()
    elif port == 40011:
        c.send(c.tp(fin=False) + a[:3])
        c.send(c.tp(seq=20) + c.ac() + read(9), corrupt=True)
        c.send(c.tp(fir=False) + a[3:])
        c.response()
    elif port == 40012:
        c.tseq_m = 63
        c.send(c.tp(fin=False) + a[:3])
        c.send(c.tp(fir=False) + a[3:])
        c.response()
    elif port == 40013:
        c.send(c.tp(fin=False) + a[:3])
        c.send(c.tp(fir=False, seq=c.tseq_m) + a[3:], src=MASTER + 1)
        c.send(c.tp(fir=False) + a[3:])
        c.response()
    elif port == 40014:
        c.send(b"", length=4)
        c.request(read(1))
    elif port == 40015:
        c.send(c.tp(fin=False) + a[:3])
        c.client(frame(0xC4, OUTSTATION, MASTER, c.tp(fir=False) + a[3:]), lost=True)
        # The outstation answers nothing; READ 2 must be parsed on its own.
        c.request(read(2))
    elif port == 40016:
        c.send(c.tp() + a)
        c.response(n=1, repeat_first=True)
    elif port == 40017:
        big = c.ac() + bytes([0x01]) + b"".join(read(n)[1:] for n in range(10, 26))
        big = big[:99]
        c.send(c.tp(fin=False) + big[:33])
        c.send(c.tp(fir=False, fin=False) + big[33:66])
        c.send(c.tp(fir=False) + big[66:])


def main():
    out = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "dnp3-transport-rules.pcap"
        )
    )
    pkts = []
    for port in range(40001, 40018):
        c = Conn(pkts, port)
        c.request(read(0))
        case(c, port)
        for n in (3, 4):
            c.request(read(n))
        c.finish()
    for i, p in enumerate(pkts):
        p.time = 1700000000 + i
    wrpcap(out, pkts)


if __name__ == "__main__":
    main()
