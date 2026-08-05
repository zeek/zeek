# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/opaque-type-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -r $TRACES/socks.pcap %INPUT >>output;
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output

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
	tbl[nanos1] = 3;  # overwerite the entry with 1
	print "zeek_init tbl:", |tbl|, tbl;
	}
