# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto ssh.spicy ./ssh-cond.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace test.hlto %INPUT | sort >output
# @TEST-EXEC: btest-diff output

event ssh::banner(i: int, software: string)
	{
	print i, software;
	}

# @TEST-START-FILE ssh.spicy
module SSH;

public type Banner = unit {
    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;
};
# @TEST-END-FILE

# @TEST-START-FILE ssh-cond.evt

protocol analyzer spicy::SSH over TCP:
    parse with SSH::Banner,
    port 22/tcp,
    replaces SSH;

on SSH::Banner -> event ssh::banner(1, self.software);
on SSH::Banner -> event ssh::banner(2, self.software);

# @TEST-END-FILE
