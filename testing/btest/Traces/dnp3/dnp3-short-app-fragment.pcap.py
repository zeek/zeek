#!/usr/bin/env python3
"""Generate DNP3 traces with application fragments too short for their header.

    python3 dnp3-short-app-fragment.pcap.py [DIR]   # default: the directory of this script

Writes dnp3-short-app-fragment.pcap (TCP) and dnp3-short-app-fragment-udp.pcap
(UDP). The master is 10.0.0.1 (address 1), the outstation 10.0.0.2 port 20000
(address 10). READ n asks for group 30 variation 1, start = stop = n, and every
READ is answered by a NULL response. A short request is a frame whose transport
segment has FIR and FIN and one application octet (the control octet, no
function code); a short response has FIR and FIN and two application octets
(control and function code, no IIN).

TCP, from source port:

  41001  READ 0, a short request, READ 1 (within the first 10 KiB)
  41002  READ 0, READ 1 (control)
  41003  READ 0, a short response, READ 1 (within the first 10 KiB)
  41004  READ 0, 40 READs of 45 object headers each for points 100-144
         (about 11 KiB), a short request, READ 1
  41005  READ 0, 100 short requests, READ 1

UDP, from source port 41006: READ 0, a short request, a short response, READ 1.

Written with the assistance of Claude (Anthropic, model claude-opus-5-5), reviewed by the author.
"""

import os
import sys

from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap


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
M, O = "10.0.0.1", "10.0.0.2"
MAC = {M: "02:00:00:00:00:01", O: "02:00:00:00:00:02"}


def read(*points):
    app = bytes([0x01])
    for n in points:
        app += bytes([30, 1, 0x00, n, n])
    return app


class Session:
    """One master/outstation association over TCP or UDP."""

    def __init__(self, pkts, port, udp=False):
        self.pkts, self.port, self.udp = pkts, port, udp
        self.t = 1000 + port % 100
        self.ms, self.os = 1000, 5000
        self.tseq = self.aseq = self.oseq = 0
        if not udp:
            self._add(M, O, "S", self.ms, 0)
            self._add(O, M, "SA", self.os, self.ms + 1)
            self.ms, self.os = self.ms + 1, self.os + 1
            self._add(M, O, "A", self.ms, self.os)

    def _add(self, src, dst, flags, seq, ack, payload=b""):
        sp, dp = (self.port, 20000) if src == M else (20000, self.port)
        l4 = (
            UDP(sport=sp, dport=dp)
            if self.udp
            else TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags, window=8192)
        )
        p = Ether(src=MAC[src], dst=MAC[dst]) / IP(src=src, dst=dst) / l4
        if payload:
            p = p / Raw(payload)
        p.time = self.t
        self.t += 0.01
        self.pkts.append(p)

    def client(self, user):
        data = frame(0xC4, OUTSTATION, MASTER, bytes([0xC0 | self.tseq]) + user)
        self.tseq = (self.tseq + 1) & 0x3F
        self._add(M, O, "PA", self.ms, self.os, data)
        self.ms += len(data)

    def server(self, user):
        data = frame(0x44, MASTER, OUTSTATION, bytes([0xC0 | self.oseq]) + user)
        self.oseq = (self.oseq + 1) & 0x3F
        self._add(O, M, "PA", self.os, self.ms, data)
        self.os += len(data)

    def request(self, app):
        self.client(bytes([0xC0 | self.aseq]) + app)
        self.server(bytes([0xC0 | self.aseq, 0x81, 0, 0]))
        self.aseq = (self.aseq + 1) & 0x0F

    def short_request(self):
        self.client(bytes([0xC0 | self.aseq]))

    def short_response(self):
        self.server(bytes([0xC0 | self.aseq, 0x81]))

    def close(self):
        if not self.udp:
            self._add(M, O, "FA", self.ms, self.os)
            self._add(O, M, "FA", self.os, self.ms + 1)
            self._add(M, O, "A", self.ms + 1, self.os + 1)


def tcp_trace():
    pkts = []
    for port in range(41001, 41006):
        s = Session(pkts, port)
        s.request(read(0))
        if port == 41001:
            s.short_request()
        elif port == 41003:
            s.short_response()
        elif port == 41004:
            for _ in range(40):
                s.request(read(*range(100, 145)))
            s.short_request()
        elif port == 41005:
            for _ in range(100):
                s.short_request()
        s.request(read(1))
        s.close()
    return pkts


def udp_trace():
    pkts = []
    s = Session(pkts, 41006, udp=True)
    s.request(read(0))
    s.short_request()
    s.short_response()
    s.request(read(1))
    return pkts


def main():
    out = (
        sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    )
    wrpcap(os.path.join(out, "dnp3-short-app-fragment.pcap"), tcp_trace())
    wrpcap(os.path.join(out, "dnp3-short-app-fragment-udp.pcap"), udp_trace())


if __name__ == "__main__":
    main()
