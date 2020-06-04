# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/writer-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -NN Demo::Foo >>output
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -r $TRACES/socks.trace Log::default_writer=Log::WRITER_FOO %INPUT | sort >>output
# @TEST-EXEC: btest-diff output

