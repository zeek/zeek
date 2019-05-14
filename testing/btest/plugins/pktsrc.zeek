# @TEST-EXEC: ${DIST}/aux/bro-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/pktsrc-plugin/* .
# @TEST-EXEC: ./configure --bro-dist=${DIST} && make
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` zeek -NN Demo::Foo  >>output
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` zeek -r foo::XXX %INPUT FilteredTraceDetection::enable=F >>output
# @TEST-EXEC: btest-diff conn.log

