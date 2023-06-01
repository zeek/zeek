# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -do export.hlto export.spicy export.evt
# @TEST-EXEC: zeek -Cr $TRACES/http/pipelined-requests.trace export.hlto %INPUT >>output
# @TEST-EXEC: test '!' -e reporter.log
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Test type export end-to-end, with access from the Zeek side. Regression test for #3083.

# @TEST-START-FILE export.spicy
module foo;

public type X = unit {
    x: uint8;
};
# @TEST-END-FILE

# @TEST-START-FILE export.evt
import foo;

protocol analyzer FOO over TCP:
    parse with foo::X,
    port 80/tcp;

export foo::X;

on foo::X -> event foo::hello(self);
# @TEST-END-FILE

event foo::hello(x: foo::X)
	{ print x; }
