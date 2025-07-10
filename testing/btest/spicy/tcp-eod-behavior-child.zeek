# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o x.hlto x.spicy x.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace Zeek::Spicy x.hlto x.zeek >output 2>&1
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Checks that a analyzer is properly finished when a protocol handle is closed.

# We use a child analyzer since this particular issue does not trigger for the root analyzer.

# @TEST-START-FILE x.spicy
module Foo;
import zeek;

public type X = unit {
    data: bytes &size=2 {
        local h = zeek::protocol_handle_get_or_create("Y");
        zeek::protocol_data_in(zeek::is_orig(), $$, h);
        zeek::protocol_handle_close(h);
    }
};

public type Y = unit {
    a: bytes &size=1;
    b: bytes &eod;
};
# @TEST-END-FILE

# @TEST-START-FILE x.evt
import Foo;

protocol analyzer X over TCP:
    parse with Foo::X;

protocol analyzer Y over TCP:
    parse with Foo::Y;

export Foo::Y;
on Foo::Y -> event foo($is_orig, self);
# @TEST-END-FILE


# @TEST-START-FILE x.zeek
event zeek_init() {
    Analyzer::register_for_port(Analyzer::ANALYZER_X, 22/tcp);
}

event foo(is_orig: bool, y: Foo::Y) {
    print is_orig, y$a, |y$b|;
}
# @TEST-END-FILE
