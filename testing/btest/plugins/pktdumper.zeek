# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/pktdumper-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -NN Demo::Foo  >>output
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -r $TRACES/port4242.trace -w foo::XXX %INPUT FilteredTraceDetection::enable=F >>output
# @TEST-EXEC: btest-diff output

