# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o dns.hlto dns.spicy ./dns.evt
# @TEST-EXEC: zeek -Cr ${TRACES}/dns/tkey.pcap dns.hlto >output 2>&1
# @TEST-EXEC: test -f conn.log
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: A UDP-only Spicy analyzer replacing dual-transport DNS must not crash when DNS traffic arrives over TCP. TCPSessionAdapter iterates its children and previously static_cast each to TCP_ApplicationAnalyzer; a UDP replacement routed onto a TCP connection is not one, so the cast segfaulted. Regression test for the segfault, related to #3787.

# @TEST-START-FILE dns.spicy
module DNS;

public type Message = unit {
    : bytes &eod;
};
# @TEST-END-FILE

# @TEST-START-FILE dns.evt

protocol analyzer spicy::DNS over UDP:
    parse with DNS::Message,
    replaces DNS;

# @TEST-END-FILE
