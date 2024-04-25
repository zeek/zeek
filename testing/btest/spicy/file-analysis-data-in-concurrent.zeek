# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto ssh.spicy ./ssh-cond.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace test.hlto %INPUT Spicy::enable_print=T >output 2>&1
# @TEST-EXEC: btest-diff output

module SSH;

global i: count = 0;

function get_file_handle(c: connection, is_orig: bool): string
	{
	return cat(c$uid, ++i);
	}

event zeek_init()
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_SPICY_SSH, 22/tcp);
	Files::register_protocol(Analyzer::ANALYZER_SSH, [$get_file_handle=SSH::get_file_handle]); # use tag of replaced analyzer
	}

# @TEST-START-FILE ssh.spicy
module SSH;

import spicy;
import zeek;

type Context = tuple<data_chunks: uint64>;

public type Banner = unit {
    %context = Context;
    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;
};

public type Data = unit {
    data: bytes &eod;
    on %done { print self.data; }
};

on Banner::%done {
    local fid1 = zeek::file_begin("foo/bar");
    local fid2 = zeek::file_begin("foo/bar");
    local fid3 = zeek::file_begin("foo/bar");
    zeek::file_data_in(b"12", fid1);
    zeek::file_data_in(b"!", fid3);
    zeek::file_data_in(b"AAA", fid2);
    zeek::file_data_in(b"@", fid3);
    zeek::file_data_in(b"34", fid1);
    zeek::file_data_in(b"#", fid3);
    zeek::file_data_in(b"56", fid1);
    zeek::file_data_in(b"BBB", fid2);
    zeek::file_data_in(b"$"); # -> fid3
    zeek::file_end(fid1);
    zeek::file_data_in(b"CCC", fid2);
    zeek::file_end(fid2);
    zeek::file_end(fid3);
}
# @TEST-END-FILE

# @TEST-START-FILE ssh-cond.evt

import zeek;

protocol analyzer spicy::SSH over TCP:
    parse originator with SSH::Banner,
    replaces SSH;

file analyzer spicy::Text:
    parse with SSH::Data,
    mime-type foo/bar;
# @TEST-END-FILE
