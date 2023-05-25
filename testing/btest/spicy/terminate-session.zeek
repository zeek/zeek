# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto test.spicy test.evt
# @TEST-EXEC: zeek -b -r ${TRACES}/dns/long-connection.pcap Zeek::Spicy test.hlto base/protocols/conn %INPUT
# @TEST-EXEC: cat conn.log | zeek-cut uid -C > conn.log2 && mv conn.log2 conn.log
# @TEST-EXEC: btest-diff conn.log
#
# @TEST-DOC: Validate that `terminate_session` indeed flushes Zeek-side connection state
#
# We expect to see two conn.log entries instead of one.

redef likely_server_ports += { 53/udp }; # avoid flipping direction after termination
redef udp_inactivity_timeout = 24hrs; # avoid long gaps to trigger removal

# @TEST-START-FILE test.spicy
module Test;

import zeek;

public type Foo = unit {
    on %done {
        self.context().counter = self.context().counter + 1;

        # close the connection if it is too long
        if ( self.context().counter >= 10 )
            zeek::terminate_session();
    }
    x : /./;

    %context = Counter;
};

type Counter = tuple<counter:int64>;

# @TEST-END-FILE

# @TEST-START-FILE test.evt
protocol analyzer spicy::Test over UDP:
    port 53/udp,
    parse originator with Test::Foo;
# @TEST-END-FILE
