# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o dns.hlto dns.spicy ./dns.evt
#
# Over UDP the replacement attaches and its event fires.
# @TEST-EXEC: zeek -Cr ${TRACES}/dns53.pcap dns.hlto %INPUT >udp.out 2>&1
# @TEST-EXEC: btest-diff udp.out
#
# Over TCP the UDP-only analyzer must be rejected, not attached.
# @TEST-EXEC: zeek -Cr ${TRACES}/dns/tkey.pcap dns.hlto %INPUT >tcp.out 2>&1
# @TEST-EXEC: test -f conn.log
# @TEST-EXEC: btest-diff tcp.out
#
# @TEST-DOC: A UDP-only Spicy analyzer replacing dual-transport DNS runs over UDP but must be rejected on a TCP session, not attached. Related to #3787.

event DnsTest::message(c: connection, is_orig: bool)
	{
	print "spicy DNS message", is_orig;
	}

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

on DNS::Message -> event DnsTest::message($conn, $is_orig);

# @TEST-END-FILE
