# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -do export.hlto export.spicy export.evt
# @TEST-EXEC: zeek -r $TRACES/http/post.trace export.hlto %INPUT >>output
# @TEST-EXEC: test '!' -e reporter.log
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Tests that named and anonymous bitfields are exported as expected.

event zeek_init() {
    Analyzer::register_for_port(Analyzer::ANALYZER_FOO, 80/tcp);
}

# @TEST-START-FILE export.spicy
module foo;

public type X = unit {
    a: uint8;

    bf: bitfield(8) {
	 x1: 0..7;
	 y1: 0..3;
	 z1: 4..7;
     };

     : bitfield(8) {
	 x2: 0..7;
	 y2: 0..3;
	 z2: 4..7;
     };

    b: uint8;
};
# @TEST-END-FILE

# @TEST-START-FILE export.evt
import foo;

protocol analyzer FOO over TCP:
    parse originator with foo::X;

export foo::X;

on foo::X -> event foo::hello(self);
# @TEST-END-FILE

event foo::hello(x: foo::X)
	{
	print record_fields(x);
	print record_fields(x$bf);
	print x;
	}
