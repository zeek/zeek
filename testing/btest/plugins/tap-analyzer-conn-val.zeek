# @TEST-DOC: A plugin hooking HookSetupAnalyzerTree() to attach a TapAnalyzer to every connection.
#
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo TapAnalyzer
# @TEST-EXEC: cp -r %DIR/tap-analyzer-conn-val-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
#
#
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::TapAnalyzer" ZEEK_PLUGIN_PATH=`pwd` zeek -b -r $TRACES/http/get.trace %INPUT >>output
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::TapAnalyzer" ZEEK_PLUGIN_PATH=`pwd` zeek -b -r $TRACES/http/get.trace %INPUT http_skip_further_processing=T >>output
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::TapAnalyzer" ZEEK_PLUGIN_PATH=`pwd` zeek -b -r $TRACES/wikipedia.trace %INPUT >>output
# @TEST-EXEC: ZEEK_PLUGIN_ACTIVATE="Demo::TapAnalyzer" ZEEK_PLUGIN_PATH=`pwd` zeek -b -r $TRACES/wikipedia.trace %INPUT http_skip_further_processing=T >>output
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

@load base/protocols/http

redef record connection += {
	tap_deliver: count &default=0;
	tap_skip: count &default=0;
};


event zeek_init()
	{
	print packet_source()$path;
	}

event zeek_done()
	{
	print "===";
	}


global http_skip_further_processing = F &redef;

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	print fmt("http_request: uid=%s deliver=%s skip=%s", c$uid, c$tap_deliver, c$tap_skip);

	if ( http_skip_further_processing )
		{
		print fmt("skip_further_processing uid=%s", c$uid);
		skip_further_processing(c$id);
		}
	}

event connection_state_remove(c: connection)
	{
	print fmt("connection_state_remove: %s deliver=%s skip=%s", c$uid, c$tap_deliver, c$tap_skip);
	}
