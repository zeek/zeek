# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: mkdir -p a/b/c && mv y.spicy a/b/c
# @TEST-EXEC: spicyz -d -o test.hlto ssh.spicy ./ssh.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace  test.hlto %INPUT >output
# @TEST-EXEC: btest-diff output

event ssh::test(x: string, y: string)
	{
	print x, y;
	}

# @TEST-START-FILE ssh.spicy
module SSH;

public type Banner = unit {
    %port = 22/tcp;

    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;

    on %done {}
};
# @TEST-END-FILE

# @TEST-START-FILE x.spicy

module X;

public function x()  : string {
    return "Foo::x";
}

# @TEST-END-FILE

# @TEST-START-FILE y.spicy

module Y;

public function y()  : string {
    return "Foo::y";
}

# @TEST-END-FILE


# @TEST-START-FILE ssh.evt
protocol analyzer spicy::SSH over TCP:
    parse with SSH::Banner;

import X;
import Y from a.b.c;

on SSH::Banner -> event ssh::test(X::x(), Y::y());
# @TEST-END-FILE
