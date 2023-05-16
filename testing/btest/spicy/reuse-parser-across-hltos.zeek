# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o foo.hlto foo.spicy foo.evt
# @TEST-EXEC: spicyz -d -o bar.hlto bar.spicy bar.evt foo.spicy
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace foo.hlto %INPUT | sort >>output
# @TEST-EXEC: echo >>output
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace bar.hlto %INPUT | sort >>output
# @TEST-EXEC: echo >>output
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace foo.hlto bar.hlto %INPUT | sort >>output
# @TEST-EXEC: echo >>output
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace bar.hlto foo.hlto %INPUT | sort >>output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Check that HLTOs remain isolated from each other when reusing another's units.
#
# The events triggered should reflect what's being loaded, and not depend on any loading ordering either.

event foo::test(x: string)
	{
	print "foo", x;
	}

event bar::test(x: string)
	{
	print "bar", x;
	}

# @TEST-START-FILE foo.spicy
module Foo;

public type Banner = unit {
    %port = 22/tcp;

    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;
};
# @TEST-END-FILE
#
# @TEST-START-FILE foo.evt
import Foo;

protocol analyzer spicy::Foo over TCP:
    parse with Foo::Banner;

on Foo::Banner -> event foo::test(self.version);
# @TEST-END-FILE

# @TEST-START-FILE bar.spicy
module Bar;

import Foo;

public type Banner = unit {
    %port = 22/tcp;
    x: Foo::Banner;
};

# @TEST-END-FILE
#
# @TEST-START-FILE bar.evt
import Foo;
import Bar;

protocol analyzer spicy::Bar over TCP:
    parse with Bar::Banner;

on Foo::Banner -> event bar::test(self.version);
# @TEST-END-FILE
