# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto test.spicy test.evt
# @TEST-EXEC: zeek test.hlto %INPUT >output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Check that we raise port events for Spicy analyzers, and that the ports get correctly registered.

event spicy_analyzer_for_port(a: Analyzer::Tag, p: port){
    print a, p;
}

event zeek_done() {
    print Analyzer::ports[Analyzer::ANALYZER_SPICY_TEST];
}

# @TEST-START-FILE test.spicy
module Test;

import zeek;

public type Message = unit {
    data: bytes &eod {}
};
# @TEST-END-FILE

# @TEST-START-FILE test.evt
protocol analyzer spicy::Test over UDP:
    parse with Test::Message,
    port 11337/udp-11340/udp,
    ports {31337/udp-31340/udp};
# @TEST-END-FILE
