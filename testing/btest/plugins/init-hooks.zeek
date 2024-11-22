# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo InitHooks
# @TEST-EXEC: cp -r %DIR/init-hooks-plugin/* .

# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
#
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -b %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff out

@load-plugin Demo::InitHooks

event zeek_init() {
	print "zeek_init";
}

event zeek_done() {
	print "zeek_done";
}
