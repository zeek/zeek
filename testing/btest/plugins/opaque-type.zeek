# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/opaque-type-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -NN Demo::Foo >>output
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -r $TRACES/socks.pcap %INPUT >>output;
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output

event zeek_init()
	{
	local nanos = nanotime();
	print "zeek_init: nanos=", nanos;
	print "zeek_init: nanos as count", nanos as count;
	print "zeek_init: nanos as time", nanos as time, strftime("%Y-%m-%d %H:%m", nanos as time);
	}
