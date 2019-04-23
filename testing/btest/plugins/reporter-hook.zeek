# @TEST-EXEC: ${DIST}/aux/bro-aux/plugin-support/init-plugin -u . Reporter Hook
# @TEST-EXEC: cp -r %DIR/reporter-hook-plugin/* .
# @TEST-EXEC: ./configure --bro-dist=${DIST} && make
# @TEST-EXEC: BRO_PLUGIN_ACTIVATE="Reporter::Hook" BRO_PLUGIN_PATH=`pwd` zeek -b %INPUT 2>&1 | $SCRIPTS/diff-remove-abspath | sort | uniq  >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath | $SCRIPTS/diff-remove-timestamps" btest-diff reporter.log

@load base/frameworks/reporter

type TestType: record {
	a: bool &optional;
};

event zeek_init()
	{
	Reporter::info("Some Info");
	Reporter::warning("A warning");
	Reporter::error("An Error");
	Reporter::error("An Error that does not show up in the log");

	# And just trigger a runtime problem.
	local b = TestType();
	print b$a;
	}
