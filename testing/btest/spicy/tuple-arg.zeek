# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto ssh.spicy ./ssh-tuple.evt
# @TEST-EXEC: HILTI_DEBUG=zeek zeek -r ${TRACES}/ssh/single-conn.trace test.hlto %INPUT | sort >output
# @TEST-EXEC: grep event .stderr | sort >>output
# @TEST-EXEC: btest-diff output

type Foo: record {
    i: int;
	s: string &optional;
};

event ssh::banner(f: Foo)
	{
	print f;
	}

# @TEST-START-FILE ssh.spicy

module SSH;

import zeek;

public type Banner = unit {
    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;

    unset_field: uint64 if ( False );

    on %done { zeek::confirm_protocol(); }
};
# @TEST-END-FILE

# @TEST-START-FILE ssh-tuple.evt

protocol analyzer spicy::SSH over TCP:
    parse originator with SSH::Banner,
    port 22/tcp,
    replaces SSH;

on SSH::Banner -> event ssh::banner((1, self.software));
on SSH::Banner -> event ssh::banner((2, self.?software));
on SSH::Banner -> event ssh::banner((3, self.?unset_field));
on SSH::Banner -> event ssh::banner((4, Null));

# @TEST-END-FILE
