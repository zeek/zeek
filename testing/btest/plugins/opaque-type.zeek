# @TEST-DOC: The plugin installs a new NanoTime type that is a derived OpaqueType with custom hashing, cast and default value implementations.
#
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/opaque-type-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek %INPUT >>output;
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output
#
# The OpaqueType::DefaultVal() isn't handled by ZAM at this point.
# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"

event zeek_init()
	{
	local nanos = nanotime();
	print "zeek_init: nanos=", nanos;
	print "zeek_init: nanos as count", nanos as count;
	print "zeek_init: nanos as time", nanos as time, strftime("%Y-%m-%d %H:%m", nanos as time);

	if ( nanos ?as string )
		print "zeek_init: ERROR nanos to string?";
	else
		print "zeek_init: nanos cannot be converted to a string";
	}

event zeek_init() &priority=-1
	{
	local nanos: NanoTime;
	print "zeek_init: default nanos=", nanos as count;
	}

event zeek_init() &priority=-2
	{
	local nanos1: NanoTime;  # Use DefaultVal()
	local nanos2: NanoTime = nanotime();

	local tbl: table[NanoTime] of count;
	tbl[nanos1] = 1;
	tbl[nanos2] = 2;
	tbl[nanos1] = 3;  # overwrite nanos1 entry with value 3
	print "zeek_init tbl:", |tbl|, tbl;
	}
