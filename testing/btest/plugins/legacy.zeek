# Test that legacy Bro plugins still work.
# @TEST-EXEC: ${DIST}/aux/zeek-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/legacy-plugin/* .
# @TEST-EXEC: ./configure --bro-dist=${DIST} && make
# @TEST-EXEC: unset ZEEK_PLUGIN_PATH; BRO_PLUGIN_PATH=`pwd` zeek -NN Demo::Foo >>output
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: unset ZEEK_PLUGIN_PATH; BRO_PLUGIN_PATH=`pwd` zeek -r $TRACES/port4242.trace %INPUT >>output
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output

event foo_message(c: connection, data: string)
	{
	print "foo_message", c$id, data;
	}

