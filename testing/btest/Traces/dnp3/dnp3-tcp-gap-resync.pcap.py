#!/usr/bin/env python3
"""Generate DNP3/TCP resynchronization edge cases with deterministic packet bytes.

    python3 dnp3-tcp-gap-resync.pcap.py [OUT]

Ports 40001-40004 reuse the four gap placements from dnp3-tcp-gap.pcap.py.
Port 40005 inserts a false 05 64 marker with a bad header CRC after a gap.
Port 40006 splits a trailing 05 from a bad-magic candidate before a valid frame.
Port 40007 has a delivery with no marker, then splits a valid 05 64 start across
TCP deliveries. Port 40008 loses the tail of an outstation response. Port 40009
has two gaps while seeking sync, followed by a valid request. Port 40010 ends
with an incomplete 05 64 05 candidate to check bounds at EOF. Port 40011 puts a
valid frame start inside a false candidate's rescan window. Port 40012 inserts
a CRC-valid candidate with an invalid link length before a valid frame. Ports
40013-40017 cover length-5 link-only frames followed by link frames, including
link-only frames between transport fragments. Ports 40018-40020 cover the
resync skip budget: exceeded after one gap, stayed under, and exceeded only
across two gaps.

Contributed by Steve Smoot in review of #6043.
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

    def server(self, data, lost=False):
        if not lost:
            self.add(self.o, self.m, 20000, self.port, self.os, self.ms, 0x18, data)
        self.os += len(data)

    def request_frame(self, app):
        # transport FIR|FIN and application control FIR|FIN, then the application data
        user = bytes([0xC0 | self.tseq_m, 0xC0 | self.aseq]) + app
        self.tseq_m = (self.tseq_m + 1) & 0x3F
        return frame(0xC4, OUTSTATION, MASTER, user)

    def request(self, app, split=False, lost=None, reply=True):
        f = self.request_frame(app)
        split_at = 10 if split is True else split if split else None
        if split_at is not None:
            self.client(f[:split_at], lost == "head")
            self.client(f[split_at:], lost == "tail")
        else:
            self.client(f, lost == "whole")
        if reply:
            self.response()
        return f

    def response(self, split_at=None, lost=None):
        user = bytes([0xC0 | self.tseq_o, 0xC0 | self.aseq, 0x81, 0x00, 0x00])
        self.tseq_o = (self.tseq_o + 1) & 0x3F
        self.aseq = (self.aseq + 1) & 0x0F
        f = frame(0x44, MASTER, OUTSTATION, user)
        if split_at is None:
            self.server(f, lost == "whole")
        else:
            self.server(f[:split_at])
            self.server(f[split_at:], lost == "tail")

    def response_with_link_status_between_transport_chunks(self):
        app = bytes([0xC0 | self.aseq, 0x81, 0x00, 0x00])
        first = frame(0x44, MASTER, OUTSTATION, bytes([0x40 | self.tseq_o]) + app[:2])
        self.tseq_o = (self.tseq_o + 1) & 0x3F
        self.server(first)
        self.server(frame(0x0B, MASTER, OUTSTATION, b""))
        last = frame(0x44, MASTER, OUTSTATION, bytes([0x80 | self.tseq_o]) + app[2:])
        self.tseq_o = (self.tseq_o + 1) & 0x3F
        self.aseq = (self.aseq + 1) & 0x0F
        self.server(last)

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
            os.path.dirname(os.path.abspath(__file__)), "dnp3-tcp-gap-resync.pcap"
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

    # A false start marker with a bad header CRC must be rejected and rescanned.
    c = Conn(pkts, 40005)
    c.request(read(0))
    c.client(b"\x11" * 5, lost=True)
    c.client(b"\x05\x64" + b"\x00" * 9)
    c.request(read(1))
    c.finish()

    # Exercise a trailing 0x05, then a non-0x64 byte, followed by a valid header.
    # This covers the candidate-magic failure while preserving the later frame.
    c = Conn(pkts, 40006)
    c.request(read(0))
    c.client(b"\x22" * 5, lost=True)
    c.client(b"\x05")
    f = c.request_frame(read(1))
    c.client(b"\x00" * 10 + f)
    c.response()
    c.finish()

    # No marker in one delivery, then a valid start marker split across deliveries.
    c = Conn(pkts, 40007)
    c.request(read(0))
    c.client(b"\x33" * 5, lost=True)
    c.client(b"\x33")
    f = c.request_frame(read(1))
    c.client(f[:1])
    c.client(f[1:])
    c.response()
    c.finish()

    # A responder-side gap inside a response frame; the next response must recover.
    c = Conn(pkts, 40008)
    c.request(read(0), reply=False)
    c.response(split_at=10, lost="tail")
    c.request(read(1), reply=False)
    c.response()
    c.finish()

    # Two gaps while seeking sync produce one weird, then a valid request resumes.
    c = Conn(pkts, 40009)
    c.request(read(0))
    c.client(b"\x44" * 5, lost=True)
    c.client(b"\x55" * 5)
    c.client(b"\x66" * 5, lost=True)
    c.client(b"\x77" * 5)
    c.request(read(1))
    c.finish()

    # A short candidate must remain buffered without reading past the received
    # bytes when the connection closes before the link header is complete.
    c = Conn(pkts, 40010)
    c.request(read(0))
    c.client(b"\x88" * 5, lost=True)
    c.client(b"\x05\x64\x05")
    c.finish()

    # The real marker begins inside the failed candidate's 11-byte window.
    # Rescanning must start at the candidate's second octet and retain the
    # partial real header until its final bytes arrive.
    c = Conn(pkts, 40011)
    c.request(read(0))
    c.client(b"\x99" * 5, lost=True)
    f = c.request_frame(read(1))
    c.client(b"\x05\x64" + f)
    c.response()
    c.finish()

    # A CRC-valid header still needs a legal DNP3 link length to be accepted.
    c = Conn(pkts, 40012)
    c.request(read(0))
    c.client(b"\xaa" * 5, lost=True)
    bad_header = bytes([0x05, 0x64, 0, 0xC4, OUTSTATION, 0, MASTER, 0])
    c.client(
        bad_header
        + crc(bad_header).to_bytes(2, "little")
        + b"\xc0"
        + c.request_frame(read(1))
    )
    c.response()
    c.finish()

    # After a gap, a link-only frame must not consume the next frame's first
    # octet, whether both frames arrive together or in separate TCP deliveries.
    link_status_request = frame(0xC9, OUTSTATION, MASTER, b"")
    c = Conn(pkts, 40013)
    c.request(read(0))
    c.client(b"\xbb" * 5, lost=True)
    c.client(link_status_request + c.request_frame(read(1)))
    c.response()
    c.finish()

    c = Conn(pkts, 40014)
    c.request(read(0))
    c.client(b"\xcc" * 5, lost=True)
    c.client(link_status_request)
    c.client(c.request_frame(read(1)))
    c.response()
    c.finish()

    # Also exercise the normal, non-gap path with one TCP delivery.
    c = Conn(pkts, 40015)
    c.request(read(0))
    c.client(link_status_request + c.request_frame(read(1)))
    c.response()
    c.finish()

    # A responder link-status frame and response can share one TCP delivery.
    c = Conn(pkts, 40016)
    c.request(read(0), reply=False)
    app = bytes([0xC0 | c.tseq_o, 0xC0 | c.aseq, 0x81, 0x00, 0x00])
    response = frame(0x44, MASTER, OUTSTATION, app)
    c.tseq_o = (c.tseq_o + 1) & 0x3F
    c.aseq = (c.aseq + 1) & 0x0F
    c.server(frame(0x0B, MASTER, OUTSTATION, b"") + response)
    c.finish()

    # A link-only frame between transport chunks must not reset fragment state.
    c = Conn(pkts, 40017)
    c.request(read(0), reply=False)
    c.response_with_link_status_between_transport_chunks()
    c.finish()

    # Resync budget (4096 skipped octets per resync episode). Junk contains no
    # 0x05, so every octet is skipped. 40018 exceeds the budget after one gap
    # and must give up; 40019 stays well under it and must recover; 40020
    # exceeds it only in total across two gaps, which must not reset it.
    for port, junk in ((40018, [5000]), (40019, [300]), (40020, [3000, 3000])):
        c = Conn(pkts, port)
        c.request(read(0))
        for n in junk:
            c.client(b"\xdd" * 5, lost=True)
            for k in range(0, n, 1000):
                c.client(b"\x11" * min(1000, n - k))
        c.request(read(1))
        c.finish()

    with open(out, "wb") as f:
        f.write(
            struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 0)
        )  # LINKTYPE_NULL
        for i, p in enumerate(pkts):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)) + p)


if __name__ == "__main__":
    main()
