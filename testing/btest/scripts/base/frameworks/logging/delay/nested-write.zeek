# @TEST-DOC: Test the behavior when a Log::write() happens within Log::log_stream_policy(), or within a post_delay_cb hook.

# @TEST-EXEC: zeek -B logging,tm -b -r $TRACES/http/get.trace test.zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# @TEST-EXEC: touch test.log && zeek-cut -m -F'|' < test.log > test.cut
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff test.cut
#
# @TEST-EXEC: touch test-other.log && zeek-cut -m -F'|' < test-other.log > test-other.cut
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff test-other.cut

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
	LOG,
	LOG_OTHER,
};

type Info: record {
	ts: time &log;
	write_ts: time &log &optional;
	uid: string &log;
	msg: string &log;
};

hook log_policy(rec: Info, id: Log::ID, filter: Log::Filter)
	{
	print network_time(), "log_policy", rec$uid, id, rec$msg;
	rec$write_ts = network_time();
	}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test", $policy=log_policy]);
	Log::create_stream(LOG_OTHER, [$columns=Info, $path="test-other", $policy=log_policy]);
	}

event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid;
	local info = Info($ts=network_time(), $uid=c$uid, $msg="inital-value");
	Log::write(LOG, info);
	}
# @TEST-END-FILE test.zeek

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	local now = network_time();
	print now, "log_stream_policy", id, rec;

	if ( id != LOG )
		return;

	# Send to the other log.
	Log::write(LOG_OTHER, rec);

	Log::delay(LOG, rec, function[now](rec2: Info, id2: Log::ID): bool {
		local delayed_for = network_time() - now;
		rec2$msg = fmt("%s delayed %s", rec2$msg, delayed_for);
		print network_time(), "post_delay_cb", rec2, delayed_for;
		return T;
	});

	when [rec] ( T == F )
		{
		}
	timeout 10msec
		{
		print network_time(), "when timeout", rec;
		}
	}

# @TEST-START-NEXT
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	local now = network_time();
	print now, "log_stream_policy", id, rec;

	if ( id != LOG )
		return;

	Log::delay(LOG, rec, function[now](rec2: Info, id2: Log::ID): bool {
		local delayed_for = network_time() - now;
		rec2$msg = fmt("%s delayed %s", rec2$msg, delayed_for);
		print network_time(), "post_delay_cb", rec2, delayed_for;
		Log::write(LOG_OTHER, rec2);

		return T;
	});

	when [rec] ( T == F )
		{
		}
	timeout 10msec
		{
		print network_time(), "when timeout", rec;
		}
	}
