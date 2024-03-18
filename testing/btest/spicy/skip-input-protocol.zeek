# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto test.spicy test.evt
# @TEST-EXEC: zeek -b -r ${TRACES}/dns/long-connection.pcap Zeek::Spicy test.hlto %INPUT "Spicy::enable_print = T;" >output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Validate that `skip_input` works for protocol analyzers.

redef likely_server_ports += { 53/udp }; # avoid flipping direction after termination
redef udp_inactivity_timeout = 24hrs; # avoid long gaps to trigger removal

event Test::foo() { print "event"; }

event zeek_init() {
    Analyzer::register_for_port(Analyzer::ANALYZER_SPICY_TEST, 53/udp);
}

# @TEST-START-FILE test.spicy
module Test;

import zeek;

type Counter = tuple<counter: int64>;

public type Foo = unit {
    %context = Counter;

    data: bytes &eod;

    on %done {
        self.context().counter = self.context().counter + 1;

        print self.context().counter, zeek::is_orig(), |self.data|;

        if ( self.context().counter == 3 )
            zeek::skip_input();
    }
};

# @TEST-END-FILE

# @TEST-START-FILE test.evt
protocol analyzer spicy::Test over UDP:
    parse with Test::Foo;

on Test::Foo -> event Test::foo();
# @TEST-END-FILE
