# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto ssh.spicy ./ssh-cond.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace test.hlto %INPUT Spicy::enable_print=T >output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Validate that `skip_input` works for file analyzers.

# @TEST-START-FILE ssh.spicy
module SSH;

import spicy;
import zeek;

public type Banner = unit {
    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;
};

type Context = tuple<counter: uint64>;

public type Data = unit {
    %context = Context;

    : (bytes &size=2)[] foreach {
        self.context().counter = self.context().counter + 1;

        print self.context().counter, $$;

        if ( self.context().counter == 3 )
            zeek::skip_input();
    }
};

on Banner::%done {
    local fid1 = zeek::file_begin("foo/bar");
    zeek::file_data_in(b"12", fid1);
    zeek::file_data_in(b"34", fid1);
    zeek::file_data_in(b"56", fid1);
    zeek::file_data_in(b"78", fid1);
    zeek::file_data_in(b"90", fid1);
    zeek::file_end(fid1);
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
