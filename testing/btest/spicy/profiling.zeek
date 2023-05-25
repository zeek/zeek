# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -Z -d -o ssh.hlto ssh.spicy ./ssh.evt
# @TEST-EXEC: zeek -b -r ${TRACES}/ssh/single-conn.trace Zeek::Spicy ssh.hlto %INPUT Spicy::enable_profiling=T >output 2>prof.log.raw
# @TEST-EXEC: cat prof.log.raw | awk '{print $1, $2}' | egrep -v 'zeek/rt/debug|zeek/rt/internal_handler' >prof.log
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff prof.log
#
# @TEST-DOC: Tests that we get profiling information for the Spicy analyzer.

event ssh::banner(c: connection, is_orig: bool, version: string, software: string)
	{
	print "SSH banner", c$id, is_orig, version, software;
	}

# @TEST-START-FILE ssh.spicy
module SSH;

import spicy;

public type Banner = unit {
    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;
};
# @TEST-END-FILE

# @TEST-START-FILE ssh.evt
protocol analyzer spicy::SSH over TCP:
    # no port, we're using the signature
    parse with SSH::Banner,
    port 22/tcp,
    replaces SSH;

on SSH::Banner -> event ssh::banner($conn, $is_orig, self.version, self.software);
# @TEST-END-FILE
