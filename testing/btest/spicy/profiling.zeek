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

event zeek_init()
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_SPICY_SSH, 22/tcp);
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
    parse with SSH::Banner,
    replaces SSH;

on SSH::Banner -> event ssh::banner($conn, $is_orig, self.version, self.software);
# @TEST-END-FILE
