# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -o test.hlto udp-test.spicy ./udp-test.evt
# @TEST-EXEC: HILTI_DEBUG=zeek zeek -Cr ${TRACES}/udp-packet.pcap test.hlto %INPUT >out 2>&1
# @TEST-EXEC: grep -e 'Scheduling analyzer' -e 'error during parsing' < out > out.filtered
# @TEST-EXEC: btest-diff out.filtered

# @TEST-DOC: Expect a single 'Scheduling analyzer ...' message in the debug output and no parsing errors. There was a bug that 'port 31336/udp' would be wrongly interpreted as a 31336/udp-31337/udp port range. Regression test for #3278.

# @TEST-START-FILE udp-test.spicy
module UDPTest;

public type Message = unit {
    data: bytes &eod {
      assert False: "not reached";
    }
};
# @TEST-END-FILE

# @TEST-START-FILE udp-test.evt
protocol analyzer spicy::UDP_TEST over UDP:
    parse with UDPTest::Message,
    port 31336/udp;
# @TEST-END-FILE
