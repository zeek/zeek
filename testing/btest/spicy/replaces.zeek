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
#
# XXX: Replaces is kin of borked. "replaces" probably should inherit/use
#      ports previously registered through Analyzer::register_for_port() for
#      the analyzer that is being replaced, but that doesn't seem to be
#      happening. Having ports previosly in .evt "worked around it" mostly.
#
#      This seems pretty much #3573.
#
event zeek_init()
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_SPICY_SSH, 22/tcp);

	# The following should maybe "do the right thing" when using replaces
	# if we fiddle with the underlying enum value?
	#
	# Analyzer::register_for_port(Analyzer::ANALYZER_SSH, 22/tcp);
	}

event ssh::banner(c: connection, is_orig: bool, version: string, software: string)
	{
	print "SSH banner", c$id, is_orig, version, software;
	}

event analyzer_confirmation_info(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo)
	{
	print atype, info$aid;
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
    replaces SSH;

on SSH::Banner -> event ssh::banner($conn, $is_orig, self.version, self.software);
# @TEST-END-FILE
