"""Generate a two-question DNS request with a CNAME-to-A response.

Questions: www.example.com A and foo.com A. The reply contains
www.example.com CNAME server.example.net and server.example.net A 1.2.3.4.
AI assistance: ChatGPT (GPT-6) assisted in preparing this generator.
"""

from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, Ether, wrpcap

questions = DNSQR(qname="www.example.com.", qtype="A", qclass="IN") / DNSQR(
    qname="foo.com.", qtype="A", qclass="IN"
)

answers = DNSRR(
    rrname="www.example.com.",
    type="CNAME",
    rclass="IN",
    ttl=3600,
    rdata="server.example.net.",
) / DNSRR(
    rrname="server.example.net.", type="A", rclass="IN", ttl=3600, rdata="1.2.3.4"
)

request = (
    Ether()
    / IP(src="192.168.1.10", dst="8.8.8.8")
    / UDP(sport=12345, dport=53)
    / DNS(id=0xCCCC, qr=0, rd=1, qdcount=2, qd=questions)
)

response = (
    Ether()
    / IP(src="8.8.8.8", dst="192.168.1.10")
    / UDP(sport=53, dport=12345)
    / DNS(id=0xCCCC, qr=1, rd=1, ra=1, qdcount=2, qd=questions, ancount=2, an=answers)
)

request.time = 1763761597.0
response.time = 1763761597.005

wrpcap(str(Path(__file__).with_suffix("")), [request, response])
