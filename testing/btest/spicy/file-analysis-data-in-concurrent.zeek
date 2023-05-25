# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto ssh.spicy ./ssh-cond.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace test.hlto %INPUT Spicy::enable_print=T >output
# @TEST-EXEC: btest-diff output

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
    port 22/tcp,
    replaces SSH;

file analyzer spicy::Text:
    parse with SSH::Data,
    mime-type foo/bar;
# @TEST-END-FILE
