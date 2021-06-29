# This doesn't work for ZAM due to inlining making the "foo" hook ineffectual.
# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"
#
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Hooks
# @TEST-EXEC: cp -r %DIR/func-hook-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::Hooks" ZEEK_PLUGIN_PATH=`pwd` zeek -b %INPUT 2>&1 | grep foo >output
# @TEST-EXEC: btest-diff output

@unload base/misc/version

function foo(a: count, b: count, c: count, s: string)
	{
	print "foo", a, b, c, s;
	}

event zeek_init()
	{
	foo(1, 2, 3, "yo");
	}
