# @TEST-DOC: Test the post delay callback and timing behavior.
#
# During new_connection() a Log::write() happens. Each packet is printed
# to observe timing behavior.
#
# @TEST-EXEC: zeek -B logging,tm -b -r $TRACES/http/get.trace test.zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# @TEST-EXEC: touch test.log && zeek-cut -m -F'|' < test.log > test.cut
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff test.cut

# @TEST-START-FILE test.zeek

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

event new_connection(c: connection)
	{
	print network_time(), "new_connection", c$uid;
	local info = Info($ts=network_time(), $uid=c$uid, $msg="inital-value");
	Log::write(LOG, info);
	}
# @TEST-END-FILE test.zeek

# Basic delay() test, no delay_finish()
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id, rec;

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

# # @TEST-START-NEXT
# Basic delay() test with delay_finish(), expect callback to be invoked
# right at Log::delay_finish()
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id, rec;

	local token = Log::delay(LOG, rec, function[now](rec2: Info, id2: Log::ID): bool {
		local delayed_for = network_time() - now;
		rec2$msg = fmt("%s delayed %s", rec2$msg, delayed_for);
		print network_time(), "post_delay_cb", rec2, delayed_for;
		return T;
	});

	when [id, rec, token] ( T == F )
		{
		}
		timeout 10msec
		{
		print network_time(), "when timeout", rec;
		Log::delay_finish(id, rec, token);
		}
	}

# # @TEST-START-NEXT
# Basic delay() test with two callbacks but just one Log::delay_finish() call.
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id, rec;

	local token1 = Log::delay(LOG, rec, function[now](rec2: Info, id2: Log::ID): bool {
		local delayed_for = network_time() - now;
		rec2$msg = fmt("%s delayed %s", rec2$msg, delayed_for);
		print network_time(), "post_delay_cb - 1", rec2, delayed_for;
		return T;
	});

	local token2 = Log::delay(LOG, rec, function(rec2: Info, id2: Log::ID): bool {
		print network_time(), "post_delay_cb - 2", rec2;
		return T;
	});

	when [id, rec, token1] ( T == F )
		{
		}
		timeout 10msec
		{
		print network_time(), "when timeout", rec;
		Log::delay_finish(id, rec, token1);
		}
	}

# # @TEST-START-NEXT
# Basic delay() test two callbacks and two Log::delay_finish() calls.
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id, rec;

	local token1 = Log::delay(LOG, rec, function[now](rec2: Info, id2: Log::ID): bool {
		local delayed_for = network_time() - now;
		rec2$msg = fmt("%s delayed %s", rec2$msg, delayed_for);
		print network_time(), "post_delay_cb - 1", rec2, delayed_for;
		return T;
	});

	local token2 = Log::delay(LOG, rec, function(rec2: Info, id2: Log::ID): bool {
		print network_time(), "post_delay_cb - 2", rec2;
		return T;
	});

	when [id, rec, token1, token2] ( T == F )
		{
		}
		timeout 10msec
		{
		print network_time(), "when timeout", rec;
		Log::delay_finish(id, rec, token1);
		Log::delay_finish(id, rec, token2);
		}
	}

# # @TEST-START-NEXT
# The delay callback suppresses the log by return F.
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id, rec;

	local token = Log::delay(LOG, rec, function[now](rec2: Info, id2: Log::ID): bool {
		local delayed_for = network_time() - now;
		print network_time(), "post_delay_cb", rec2, delayed_for;
		return F;
	});

	when [id, rec, token] ( T == F )
		{
		}
		timeout 10msec
		{
		print network_time(), "when timeout", rec;
		Log::delay_finish(id, rec, token);
		}
	}

# # @TEST-START-NEXT
# Do a delay and immediate release with a callback.
hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id, rec;

	local token = Log::delay(LOG, rec, function[now](rec2: Info, id2: Log::ID): bool {
		local delayed_for = network_time() - now;
		print network_time(), "post_delay_cb", rec2, delayed_for;
		return T;
	});
	Log::delay_finish(id, rec, token);
	}
