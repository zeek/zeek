# @TEST-DOC: Regression test for #5548. This is based on logging-hooks.zeek, but Log::enable_local_logging is set to F such that no WriterBackend is instantiated. There was a use-after-free bug due accessing threading::Fields.
#
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Log Hooks
# @TEST-EXEC: cp -r %DIR/logging-hooks-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Log::Hooks" ZEEK_PLUGIN_PATH=`pwd` zeek -b %INPUT 2>&1 | $SCRIPTS/diff-remove-abspath | sort | uniq  >output
# @TEST-EXEC: btest-diff output
#

redef Log::enable_local_logging = F;
redef LogAscii::empty_field = "EMPTY";

module SSH;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		b: bool;
		i: int &optional;
		c: count;
	} &log;
}

event zeek_init()
	{
	Log::create_stream(SSH::LOG, [$columns=Log]);

	local i = 0;
	while ( ++i < 4 )
		Log::write(SSH::LOG, [$b=T, $i=-i, $c=i]);
	}
