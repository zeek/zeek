# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o dns.hlto dns.spicy ./dns.evt
# @TEST-EXEC: zeek -Cr ${TRACES}/dns/tkey.pcap dns.hlto %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff dns.log
#
# @TEST-DOC: A UDP-only Spicy analyzer replacing dual-transport DNS must not claim DNS traffic over TCP. The built-in DNS analyzer keeps handling TCP/53, producing dns.log with proto=tcp. Companion to replaces-transport-tcp-child (the crash-safety regression); this asserts the transport-aware replaces routing. Related to #3787.

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	print "dns_message (builtin)", c$id$resp_p, get_port_transport_proto(c$id$resp_p);
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

# @TEST-END-FILE
