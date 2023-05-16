# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -o test.hlto udp-test.spicy ./udp-test.evt
# @TEST-EXEC: zeek -Cr ${TRACES}/udp-packet.pcap test.hlto %INPUT >output
# @TEST-EXEC: btest-diff output

event zeek_init()
	{
	# Check we can access the tag.
	print Analyzer::ANALYZER_SPICY_UDP_TEST;
	}

event udp_test::message(c: connection, is_orig: bool, data: string)
	{
	print "UDP packet", c$id, is_orig, data;
	}

# @TEST-START-FILE udp-test.spicy
module UDPTest;

public type Message = unit {
    data: bytes &eod;
};
# @TEST-END-FILE

# @TEST-START-FILE udp-test.evt
protocol analyzer spicy::UDP_TEST over UDP:
    parse with UDPTest::Message,
    port 11337/udp-11340/udp,
    ports {31337/udp-31340/udp};

on UDPTest::Message -> event udp_test::message($conn, $is_orig, self.data);
# @TEST-END-FILE
