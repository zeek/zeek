# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Iosource
# @TEST-EXEC: cp -r %DIR/iosource-plugin/* .

# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
#
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -Bmain-loop -b %INPUT -r $TRACES/wikipedia.trace > output
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output

@load-plugin Demo::Iosource

global flushes = 0;
global packets = 0;

# Default is 100 for pcaps, but that only triggers a single Poll() when
# reading wikipedia.trace. Tune it down a bit so Process on the FdSources
# is called more often.
redef io_poll_interval_default = 10;

event zeek_init() {
	print network_time(), "zeek_init";
}

event network_time_init() {
	print network_time(), "network_time_init";
}

event raw_packet(p: raw_pkt_hdr)
	{
	++packets;
	print network_time(), "raw_packet", packets;
	}

event event_queue_flush_point() {
	++flushes;
	print network_time(), "event_queue_flush_point", flushes;
}

event net_done(ts: time) {
	print network_time(), "net_done", ts;
}

event zeek_done() {
	print network_time(), "zeek_done";
	print network_time(), "flushes", flushes, "packets", packets;
}
