# @TEST-EXEC: ${DIST}/aux/bro-aux/plugin-support/init-plugin Demo Foo
# @TEST-EXEC: cp -r %DIR/analyzer-plugin/* .
# @TEST-EXEC: make BRO=${DIST}
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro -NN | awk '/^Demo::/ {p=1; print; next} /^[^ ]/{p=0} p==1{print}' >>output
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` bro -r $TRACES/port4242.trace %INPUT >>output
# @TEST-EXEC: btest-diff output

event foo_message(c: connection, data: string)
	{
	print "foo_message", c$id, data;
	}

