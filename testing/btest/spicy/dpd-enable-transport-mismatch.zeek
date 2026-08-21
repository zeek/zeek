# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o foo.hlto foo.spicy ./foo.evt
# @TEST-EXEC: zeek -b -r ${TRACES}/ssh/single-conn.pcap -s ./foo.sig Zeek::Spicy base/protocols/conn foo.hlto %INPUT >out 2>&1
# @TEST-EXEC: test -f conn.log
# @TEST-EXEC: btest-diff out
#
# @TEST-DOC: A UDP-only Spicy analyzer enabled via DPD signature on a TCP connection must be rejected, not attached. Related to #3787.

event FooTest::message(c: connection, is_orig: bool)
	{
	print "spicy Foo message", is_orig;
	}

# @TEST-START-FILE foo.spicy
module Foo;

public type Message = unit {
    : bytes &eod;
};
# @TEST-END-FILE

# @TEST-START-FILE foo.sig
signature foo {
    ip-proto == tcp
    payload /./
    enable "spicy_Foo"
}
# @TEST-END-FILE

# @TEST-START-FILE foo.evt

protocol analyzer spicy::Foo over UDP:
    parse with Foo::Message;

on Foo::Message -> event FooTest::message($conn, $is_orig);

# @TEST-END-FILE
