# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . LLDemo Bar
# @TEST-EXEC: cp -r %DIR/ll-protocol-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -NN LLDemo::Bar >>output
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -r $TRACES/raw_packets.trace %INPUT >>output
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output

event bar_message(dsap: count, ssap: count, control: count)
	{
	print fmt("bar_message (DSAP = %x, SSAP = %x, Control = %x)",
	 dsap, ssap, control);
	}

