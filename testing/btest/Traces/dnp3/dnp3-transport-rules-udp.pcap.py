#!/usr/bin/env python3
"""Generate a DNP3/UDP trace that exercises the pseudo-transport rules (scapy).

    python3 dnp3-transport-rules-udp.pcap.py [OUT]   # default: dnp3-transport-rules-udp.pcap next to this script

One UDP flow from a master at 10.0.0.1:40001 (address 1) to an outstation at
10.0.0.2:20000 (address 10), one link frame per datagram. The master sends READs of
group 30 variation 1 with start = stop = n ("READ n"):

  READ 0  whole (control)
  READ 1  in three segments, the middle one sent twice: accepted once
  READ 2  in two segments with a stray segment (sequence 9) between them: accepted
  READ 3  in two segments with a FIR frame between them whose data CRC is corrupt
          (READ 9): that frame is dropped, READ 3 is accepted
  READ 4  whole (control)

The outstation answers each READ; the answer to READ 1 carries the requested point
and comes in two segments, the first one sent twice.

Written with the assistance of Claude (Anthropic, model claude-opus-5-5), reviewed by the author.
"""

import os
import sys

from scapy.all import IP, UDP, Ether, Raw, wrpcap


def crc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if c & 1 else c >> 1
    return ~c & 0xFFFF


def frame(ctl, dst, src, user, corrupt=False):
    h = bytes(
        [0x05, 0x64, 5 + len(user), ctl, dst & 0xFF, dst >> 8, src & 0xFF, src >> 8]
    )
    out = bytearray(h + crc(h).to_bytes(2, "little"))
    for i in range(0, len(user), 16):
        b = bytes(user[i : i + 16])
        c = crc(b) ^ (0xFFFF if corrupt else 0)
        out += b + c.to_bytes(2, "little")
    return bytes(out)


OUTSTATION, MASTER = 10, 1
M, O = "10.0.0.1", "10.0.0.2"
MAC = {M: "02:00:00:00:00:01", O: "02:00:00:00:00:02"}

pkts = []
tseq = {M: 0, O: 0}
aseq = 0


def dgram(src, user, corrupt=False):
    dst = O if src == M else M
    sport, dport = (40001, 20000) if src == M else (20000, 40001)
    ctl, laddr = (
        (0xC4, (OUTSTATION, MASTER)) if src == M else (0x44, (MASTER, OUTSTATION))
    )
    p = (
        Ether(src=MAC[src], dst=MAC[dst])
        / IP(src=src, dst=dst, id=0, flags="DF", ttl=64)
        / UDP(sport=sport, dport=dport)
        / Raw(frame(ctl, laddr[0], laddr[1], user, corrupt))
    )
    pkts.append(p)


def tp(src, fir=True, fin=True, seq=None):
    if seq is None:
        seq = tseq[src]
        tseq[src] = (tseq[src] + 1) & 0x3F
    return bytes([(0x40 if fir else 0) | (0x80 if fin else 0) | seq])


def read(n):
    return bytes([0xC0 | aseq, 0x01, 30, 1, 0x00, n, n])


def response(n=None):
    global aseq
    app = bytes([0xC0 | aseq, 0x81, 0x00, 0x00])
    if n is not None:
        app += bytes([30, 1, 0x00, n, n, 0x01]) + n.to_bytes(4, "little")
    aseq = (aseq + 1) & 0x0F
    if n is None:
        dgram(O, tp(O) + app)
        return
    first = tp(O, fin=False) + app[:6]
    dgram(O, first)
    dgram(O, first)
    dgram(O, tp(O, fir=False) + app[6:])


def main():
    out = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "dnp3-transport-rules-udp.pcap"
        )
    )

    dgram(M, tp(M) + read(0))
    response()

    a = read(1)
    dgram(M, tp(M, fin=False) + a[:2])
    mid = tseq[M]
    dgram(M, tp(M, fir=False, fin=False) + a[2:4])
    dgram(M, tp(M, fir=False, fin=False, seq=mid) + a[2:4])
    dgram(M, tp(M, fir=False) + a[4:])
    response(1)

    a = read(2)
    dgram(M, tp(M, fin=False) + a[:3])
    dgram(M, tp(M, fir=False, fin=False, seq=9) + a[3:])
    dgram(M, tp(M, fir=False) + a[3:])
    response()

    a = read(3)
    dgram(M, tp(M, fin=False) + a[:3])
    dgram(M, tp(M, seq=20) + read(9), corrupt=True)
    dgram(M, tp(M, fir=False) + a[3:])
    response()

    dgram(M, tp(M) + read(4))
    response()

    for i, p in enumerate(pkts):
        p.time = 1700000000 + i
    wrpcap(out, pkts)


if __name__ == "__main__":
    main()
