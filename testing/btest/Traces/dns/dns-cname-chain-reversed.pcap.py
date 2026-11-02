"""Generate multi-question DNS traffic with a reversed-order CNAME chain.

Questions: www.example.com A and foo.com A. The response records occur in
reverse dependency order: server.example.net A 1.2.3.4, then
alias.example.net CNAME server.example.net, then
www.example.com CNAME alias.example.net.
AI assistance: ChatGPT (GPT-6) assisted in preparing this generator.
"""

from pathlib import Path

from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, wrpcap

questions = (
    DNSQR(qname="www.example.com.", qtype="A", qclass="IN") /
    DNSQR(qname="foo.com.", qtype="A", qclass="IN")
)

answers = (
    DNSRR(
        rrname="server.example.net.",
        type="A", rclass="IN", ttl=3600,
        rdata="1.2.3.4"
    ) /
    DNSRR(
        rrname="alias.example.net.",
        type="CNAME", rclass="IN", ttl=3600,
        rdata="server.example.net."
    ) /
    DNSRR(
        rrname="www.example.com.",
        type="CNAME", rclass="IN", ttl=3600,
        rdata="alias.example.net."
    )
)

request = (
    Ether() /
    IP(src="192.0.2.10", dst="192.0.2.53") /
    UDP(sport=53037, dport=53) /
    DNS(id=20535, qr=0, rd=1, qdcount=2, qd=questions)
)

response = (
    Ether() /
    IP(src="192.0.2.53", dst="192.0.2.10") /
    UDP(sport=53, dport=53037) /
    DNS(
        id=20535,
        qr=1,
        aa=1,
        rd=1,
        ra=1,
        qdcount=2,
        qd=questions,
        ancount=3,
        an=answers
    )
)

request.time = 1700000000.0
response.time = 1700000000.1

wrpcap(str(Path(__file__).with_suffix("")), [request, response])
