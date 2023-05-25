# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: mkdir -p modules
# @TEST-EXEC: spicyz -d -o modules/ssh.hlto ssh.spicy ./ssh.evt
# @TEST-EXEC: ZEEK_SPICY_MODULE_PATH=$(pwd)/modules zeek -r ${TRACES}/ssh/single-conn.trace %INPUT | sort >output
# @TEST-EXEC: btest-diff output
#
# We use the module search path for loading here as a regression test for #137.
# Note that this that problem only showed up when the Spicy plugin was built
# into Zeek.

event ssh::banner(c: connection, is_orig: bool, version: string, software: string)
	{
	print "SSH banner", c$id, is_orig, version, software;
	}

event analyzer_confirmation(c: connection, atype: AllAnalyzers::Tag, aid: count)
    {
    print atype, aid;
    }

# @TEST-START-FILE ssh.spicy
module SSH;

import zeek;

public type Banner = unit {
    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;

    on %done { zeek::confirm_protocol(); }
};
# @TEST-END-FILE

# @TEST-START-FILE ssh.evt

protocol analyzer spicy::SSH over TCP:
    parse with SSH::Banner,
    port 22/tcp,
    replaces SSH;

on SSH::Banner -> event ssh::banner($conn, $is_orig, self.version, self.software);
# @TEST-END-FILE
