"""Generate DNS messages with 50 and 51 answer records.

Verify the boundary of the multi-question answer association limit.
AI assistance: ChatGPT (GPT-6) assisted in preparing this generator.
"""

from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, DNSRROPT, IP, UDP, wrpcap


def make_exchange(answer_count, trans_id, timestamp):
    questions = DNSQR(qname="foo.com.", qtype="A") / DNSQR(
        qname="bar.com.", qtype="AAAA"
    )

    answers = DNSRR(rrname="foo.com.", type="A", ttl=3600, rdata="1.2.3.4")

    for _ in range(answer_count - 2):
        answers /= DNSRR(rrname="foo.com.", type="A", ttl=3600, rdata="1.2.3.4")

    answers /= DNSRR(rrname="bar.com.", type="AAAA", ttl=3600, rdata="2001:db8::1")

    request = (
        IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=12345, dport=53)
        / DNS(
            id=trans_id,
            qr=0,
            rd=1,
            qdcount=2,
            qd=questions,
            arcount=1,
            ar=DNSRROPT(rclass=4096),
        )
    )

    response = (
        IP(src="8.8.8.8", dst="192.168.1.10")
        / UDP(sport=53, dport=12345)
        / DNS(
            id=trans_id,
            qr=1,
            rd=1,
            ra=1,
            qdcount=2,
            qd=questions,
            ancount=answer_count,
            an=answers,
            arcount=1,
            ar=DNSRROPT(rclass=4096),
        )
    )

    request.time = timestamp
    response.time = timestamp + 0.005

    return [request, response]


packets = []
packets.extend(make_exchange(50, 0xBBC0, 1763761597.0))
packets.extend(make_exchange(51, 0xBBC1, 1763761598.0))

# Raw IP packets do not require Ethernet MAC addresses.
assert all(isinstance(pkt, IP) for pkt in packets)

wrpcap(str(Path(__file__).with_suffix("")), packets)
