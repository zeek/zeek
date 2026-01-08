# @TEST-DOC: Check usage delay in when statements.

# @TEST-EXEC: zeek -B tm,logging -b -r $TRACES/http/get.trace test.zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff-cut -m -F'|' test.log

# @TEST-START-FILE test.zeek
# Debug printing
global packet_count = 0;
event new_packet(c: connection, p: pkt_hdr)
	{
	++packet_count;
	print network_time(), "new_packet", packet_count;
	}

event Pcap::file_done(p: string)
	{
	print network_time(), "Pcap::file_done";
	}

redef enum Log::ID += {
	LOG
};

type Info: record {
	ts: time &log;
	write_ts: time &log &optional;
	uid: string &log;
	msg: string &log;
};

hook log_policy(rec: Info, id: Log::ID, filter: Log::Filter)
	{
	print network_time(), "log_policy", rec$uid;
	rec$write_ts = network_time();
	}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test", $policy=log_policy]);
	}
# @TEST-END-FILE test.zeek

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id, rec;

	Log::delay(LOG, rec, function[now](rec2: Info, id2: Log::ID): bool {
		local delayed_for = network_time() - now;
		rec2$msg = fmt("%s delayed %s", rec2$msg, delayed_for);
		print network_time(), "post_delay_cb", rec2;
		return T;
	});
	}

event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid;

	# Using an anonymous record type with field reordering.
	#
	# This is quirky: Because internally this record is coerced
	# very early on, the hooks and delay pipeline work with a different
	# record val ptr. So an update of this record is not visible!
	local info = [$msg="initial-value", $ts=network_time(), $uid=c$uid];

	Log::write(LOG, info);

	# Not visible after delay due to record coercion.
	print network_time(), "Updating info$msg after write!";
	info$msg = "after-write";
	}
