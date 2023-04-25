# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -o ssh.hlto ssh.spicy ssh.evt
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace ssh.hlto %INPUT ENABLE=T >>output;
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace ssh.hlto %INPUT ENABLE=F >>output;
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Check operation of Spicy::{enable,disable}_protocol_analyzer()

const ENABLE = T &redef;

event zeek_init() {
    if ( ENABLE )
        Spicy::enable_protocol_analyzer(Analyzer::ANALYZER_SPICY_SSH);
    else
        Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_SSH);
}

event ssh::banner(c: connection, is_orig: bool, version: string, software: string)
	{
	print "Spicy: SSH banner", c$id, is_orig, version, software;
	}

# @TEST-START-FILE ssh.spicy
module SSH;

import zeek;

public type Banner = unit {
    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;
};
# @TEST-END-FILE

# @TEST-START-FILE ssh.evt
protocol analyzer spicy::SSH over TCP:
    port 22/tcp,
    parse originator with SSH::Banner;

on SSH::Banner -> event ssh::banner($conn, $is_orig, self.version, self.software);
# @TEST-END-FILE
