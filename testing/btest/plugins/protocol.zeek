# @TEST-EXEC: ${DIST}/aux/bro-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/protocol-plugin/* .
# @TEST-EXEC: ./configure --bro-dist=${DIST} && make
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` zeek -NN Demo::Foo >>output
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` zeek -r $TRACES/port4242.trace %INPUT >>output
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output

event foo_message(c: connection, data: string)
	{
	print "foo_message", c$id, data;
	}

