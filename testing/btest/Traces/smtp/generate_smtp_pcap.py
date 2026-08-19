#!/usr/bin/env python3
"""Generate a pcap file containing a single fake SMTP session (TCP handshake,
SMTP command/response exchange, and teardown) using scapy.

The number of RCPT TO commands, the number of "To:" header lines in the message body, the
number of "CC:" header lines in the message body, and the number of "Received:" (mail
path) header lines are all configurable from the command line.

Example:
    ./generate_smtp_pcap.py --rcpt 4 --to 2 --cc 5 --paths 3 -o smtp.pcap

"""

import argparse
import random
import string

from scapy.all import IP, TCP, Ether, wrpcap

MONTHS = [
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
]
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def random_word(min_len=4, max_len=10):
    length = random.randint(min_len, max_len)
    return "".join(random.choices(string.ascii_lowercase, k=length))


def random_hostname():
    return f"{random_word()}.{random_word(2, 3)}.{random.choice(['com', 'net', 'org', 'example'])}"


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def random_email(domain=None):
    return f"{random_word()}@{domain or random_hostname()}"


def random_datetime_str():
    day_name = random.choice(DAYS)
    day = random.randint(1, 28)
    month = random.choice(MONTHS)
    year = random.randint(2020, 2026)
    hh, mm, ss = random.randint(0, 23), random.randint(0, 59), random.randint(0, 59)
    return f"{day_name}, {day:02d} {month} {year} {hh:02d}:{mm:02d}:{ss:02d} +0000"


def random_received_line():
    """One fake 'Received:' mail-path header, as added by a relay hop."""
    from_host = random_hostname()
    from_ip = random_ip()
    by_host = random_hostname()
    ident = "".join(random.choices(string.hexdigits.lower(), k=12))
    return (
        f"Received: from {from_host} ([{from_ip}])\r\n"
        f"\tby {by_host} with ESMTP id {ident};\r\n"
        f"\t{random_datetime_str()}"
    )


class SMTPSessionBuilder:
    """Hand-crafts the raw Ethernet/IP/TCP packets for a fake SMTP session."""

    def __init__(self, client_ip, server_ip, client_port, server_port):
        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port
        self.client_seq = random.randint(1_000_000, 4_000_000_000)
        self.server_seq = random.randint(1_000_000, 4_000_000_000)
        self.packets = []

    def handshake(self):
        syn = (
            Ether()
            / IP(src=self.client_ip, dst=self.server_ip)
            / TCP(
                sport=self.client_port,
                dport=self.server_port,
                flags="S",
                seq=self.client_seq,
            )
        )
        self.packets.append(syn)
        self.client_seq += 1

        synack = (
            Ether()
            / IP(src=self.server_ip, dst=self.client_ip)
            / TCP(
                sport=self.server_port,
                dport=self.client_port,
                flags="SA",
                seq=self.server_seq,
                ack=self.client_seq,
            )
        )
        self.packets.append(synack)
        self.server_seq += 1

        ack = (
            Ether()
            / IP(src=self.client_ip, dst=self.server_ip)
            / TCP(
                sport=self.client_port,
                dport=self.server_port,
                flags="A",
                seq=self.client_seq,
                ack=self.server_seq,
            )
        )
        self.packets.append(ack)

    # Max TCP payload per segment: Ethernet MTU (1500) minus IP (20) and TCP (20) headers.
    MSS = 1460

    def _chunks(self, payload):
        for i in range(0, len(payload), self.MSS):
            yield payload[i : i + self.MSS]

    def server_send(self, data):
        payload = data.encode()
        for chunk in self._chunks(payload):
            pkt = (
                Ether()
                / IP(src=self.server_ip, dst=self.client_ip)
                / TCP(
                    sport=self.server_port,
                    dport=self.client_port,
                    flags="PA",
                    seq=self.server_seq,
                    ack=self.client_seq,
                )
                / chunk
            )
            self.packets.append(pkt)
            self.server_seq += len(chunk)

        ack = (
            Ether()
            / IP(src=self.client_ip, dst=self.server_ip)
            / TCP(
                sport=self.client_port,
                dport=self.server_port,
                flags="A",
                seq=self.client_seq,
                ack=self.server_seq,
            )
        )
        self.packets.append(ack)

    def client_send(self, data):
        payload = data.encode()
        for chunk in self._chunks(payload):
            pkt = (
                Ether()
                / IP(src=self.client_ip, dst=self.server_ip)
                / TCP(
                    sport=self.client_port,
                    dport=self.server_port,
                    flags="PA",
                    seq=self.client_seq,
                    ack=self.server_seq,
                )
                / chunk
            )
            self.packets.append(pkt)
            self.client_seq += len(chunk)

        ack = (
            Ether()
            / IP(src=self.server_ip, dst=self.client_ip)
            / TCP(
                sport=self.server_port,
                dport=self.client_port,
                flags="A",
                seq=self.server_seq,
                ack=self.client_seq,
            )
        )
        self.packets.append(ack)

    def close(self):
        finack = (
            Ether()
            / IP(src=self.client_ip, dst=self.server_ip)
            / TCP(
                sport=self.client_port,
                dport=self.server_port,
                flags="FA",
                seq=self.client_seq,
                ack=self.server_seq,
            )
        )
        self.packets.append(finack)
        self.client_seq += 1

        ack = (
            Ether()
            / IP(src=self.server_ip, dst=self.client_ip)
            / TCP(
                sport=self.server_port,
                dport=self.client_port,
                flags="A",
                seq=self.server_seq,
                ack=self.client_seq,
            )
        )
        self.packets.append(ack)

        finack2 = (
            Ether()
            / IP(src=self.server_ip, dst=self.client_ip)
            / TCP(
                sport=self.server_port,
                dport=self.client_port,
                flags="FA",
                seq=self.server_seq,
                ack=self.client_seq,
            )
        )
        self.packets.append(finack2)
        self.server_seq += 1

        ack2 = (
            Ether()
            / IP(src=self.client_ip, dst=self.server_ip)
            / TCP(
                sport=self.client_port,
                dport=self.server_port,
                flags="A",
                seq=self.client_seq,
                ack=self.server_seq,
            )
        )
        self.packets.append(ack2)


def build_message(from_addr, to_count, cc_count, path_count, subject):
    """Build the RFC 5322 message body used as the DATA payload."""
    lines = []

    for _ in range(path_count):
        lines.append(random_received_line())

    to_addrs = [random_email() for _ in range(max(to_count, 1))]
    for addr in to_addrs:
        lines.append(f"To: {addr}")

    cc_addrs = [random_email() for _ in range(max(cc_count, 1))]
    for addr in cc_addrs:
        lines.append(f"CC: {addr}")

    lines.append(f"From: {from_addr}")
    lines.append(f"Subject: {subject}")
    lines.append(f"Date: {random_datetime_str()}")
    lines.append(f"Message-ID: <{random_word(16, 16)}@{random_hostname()}>")
    lines.append("MIME-Version: 1.0")
    lines.append("Content-Type: text/plain; charset=us-ascii")
    lines.append("")
    lines.append("This is a test message generated by generate_smtp_pcap.py.")

    return "\r\n".join(lines)


def build_session(args):
    session = SMTPSessionBuilder(
        client_ip=args.client_ip,
        server_ip=args.server_ip,
        client_port=args.client_port,
        server_port=args.server_port,
    )
    session.handshake()

    client_host = random_hostname()
    server_host = random_hostname()
    from_addr = random_email()
    rcpt_addrs = [random_email() for _ in range(max(args.rcpt, 1))]

    session.server_send(f"220 {server_host} ESMTP ready\r\n")

    session.client_send(f"EHLO {client_host}\r\n")
    session.server_send(
        f"250-{server_host} Hello {client_host}\r\n"
        "250-PIPELINING\r\n"
        "250-8BITMIME\r\n"
        "250 SIZE 35882577\r\n"
    )

    session.client_send(f"MAIL FROM:<{from_addr}>\r\n")
    session.server_send("250 OK\r\n")

    for addr in rcpt_addrs:
        session.client_send(f"RCPT TO:<{addr}>\r\n")
        session.server_send("250 OK\r\n")

    session.client_send("DATA\r\n")
    session.server_send("354 Start mail input; end with <CRLF>.<CRLF>\r\n")

    message = build_message(from_addr, args.to, args.cc, args.paths, args.subject)
    session.client_send(message + "\r\n.\r\n")
    session.server_send("250 OK: queued as 12345\r\n")

    session.client_send("QUIT\r\n")
    session.server_send(f"221 {server_host} Bye\r\n")

    session.close()
    return session.packets


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate a pcap of a fake SMTP session with scapy."
    )
    parser.add_argument(
        "-o",
        "--output",
        default="smtp.pcap",
        help="Output pcap file (default: smtp.pcap)",
    )
    parser.add_argument(
        "--rcpt",
        type=int,
        default=3,
        help="Number of RCPT TO command lines (default: 3)",
    )
    parser.add_argument(
        "--cc", type=int, default=3, help="Number of CC TO command lines (default: 3)"
    )
    parser.add_argument(
        "--to",
        type=int,
        default=1,
        help="Number of To: header lines in the message (default: 1)",
    )
    parser.add_argument(
        "--paths",
        type=int,
        default=1,
        help="Number of Received: (mail path) header lines (default: 1)",
    )
    parser.add_argument(
        "--subject",
        default="Test message",
        help="Subject header text (default: 'Test message')",
    )
    parser.add_argument(
        "--client-ip", default="10.0.0.1", help="Client (sending) IP address"
    )
    parser.add_argument(
        "--server-ip", default="10.0.0.2", help="Server (receiving) IP address"
    )
    parser.add_argument(
        "--client-port",
        type=int,
        default=None,
        help="Client source port (default: random ephemeral port)",
    )
    parser.add_argument(
        "--server-port", type=int, default=25, help="Server port (default: 25)"
    )
    parser.add_argument(
        "--seed", type=int, default=None, help="Random seed, for reproducible output"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    if args.client_port is None:
        args.client_port = random.randint(1024, 65535)

    packets = build_session(args)
    wrpcap(args.output, packets)
    print(
        f"Wrote {len(packets)} packets to {args.output} "
        f"(rcpt={args.rcpt}, to={args.to}, cc={args.cc}, paths={args.paths})"
    )


if __name__ == "__main__":
    main()
