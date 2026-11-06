#!/usr/bin/env python3
"""Generate a Modbus/TCP trace in which each connection loses one TCP segment (no dependencies).

    python3 modbus-tcp-gap.pcap.py [OUT]   # default: modbus-tcp-gap.pcap next to this script

Four connections from a client at 10.0.0.1 to a server at 10.0.0.2:502. On each, the client
sends 10 Read Holding Registers requests (transaction ids 0 to 9, address = transaction id,
except on port 40004) and the server answers each one. One client-to-server segment is missing from each
connection, so the analyzer sees a TCP gap:

  port 40001  one segment per ADU; request 4 is lost whole
  port 40002  every ADU in two 6-octet segments; the second half of request 4 is lost
  port 40003  the same split; the first half (the MBAP header) of request 4 is lost
  port 40004  the same as 40003, but every request reads 10 registers at address 0, so what
              is left of request 4 (01 03 00 00 00 0a) looks like an MBAP header with
              protocol id 0 and length 10

Written with the assistance of Claude (Anthropic, model claude-opus-5-5), reviewed by the author.
"""
import os
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack(f'!{len(b) // 2}H', b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def packet(src, dst, sport, dport, seq, ack, flags, payload=b''):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    pseudo = struct.pack('!4s4sBBH', src, dst, 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00' + ip + tcp  # DLT_NULL, AF_INET


def mbap(tid, pdu, unit=1):
    return struct.pack('!HHHB', tid, 0, 1 + len(pdu), unit) + pdu


def connection(pkts, port, lost, quantity=1):
    c, s = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
    cs, ss = 1000, 5000
    pkts.append(packet(c, s, port, 502, cs, 0, 0x02))
    pkts.append(packet(s, c, 502, port, ss, cs + 1, 0x12))
    cs, ss = cs + 1, ss + 1
    pkts.append(packet(c, s, port, 502, cs, ss, 0x10))
    for tid in range(10):
        req = mbap(tid, struct.pack('!BHH', 3, tid if quantity == 1 else 0, quantity))
        segs = [req] if lost == 'whole' else [req[:6], req[6:]]
        for i, seg in enumerate(segs):
            gone = tid == 4 and (lost == 'whole' or (lost == 'tail' and i == 1) or (lost == 'head' and i == 0))
            if not gone:
                pkts.append(packet(c, s, port, 502, cs, ss, 0x18, seg))
            cs += len(seg)
        resp = mbap(tid, struct.pack('!BB', 3, 2 * quantity) + struct.pack('!H', tid) * quantity)
        pkts.append(packet(s, c, 502, port, ss, cs, 0x18, resp))
        ss += len(resp)
    pkts.append(packet(c, s, port, 502, cs, ss, 0x11))
    pkts.append(packet(s, c, 502, port, ss, cs + 1, 0x11))
    pkts.append(packet(c, s, port, 502, cs + 1, ss + 1, 0x10))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                              'modbus-tcp-gap.pcap')
    pkts = []
    connection(pkts, 40001, 'whole')
    connection(pkts, 40002, 'tail')
    connection(pkts, 40003, 'head')
    connection(pkts, 40004, 'head', quantity=10)
    with open(out, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 0))  # LINKTYPE_NULL
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


if __name__ == '__main__':
    main()
