# @TEST-DOC: Delay queue testing.

# @TEST-EXEC: zeek -B logging,tm -b -r $TRACES/http/get.trace test.zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# @TEST-EXEC: zeek-cut -m -F'|' < test.log > test.cut
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff test.cut

# @TEST-START-FILE test.zeek
# Used by all tests below.

# Debug printing
global packet_count = 0;

redef enum Log::ID += {
	LOG
};

type Info: record {
	ts: time &log;
	post_ts: time &log &optional;
	write_ts: time &log &optional;
	msg: string &log;
};

event new_packet(c: connection, p: pkt_hdr)
	{
	++packet_count;
	print network_time(), "new_packet", packet_count;
	local info = Info($ts=network_time(), $msg=fmt("packet number %s", packet_count));
	Log::write(LOG, info);
	}


hook log_policy(rec: Info, id: Log::ID, filter: Log::Filter)
	{
	print network_time(), "log_policy";
	rec$write_ts = network_time();
	}

event Pcap::file_done(p: string)
	{
	print network_time(), "Pcap::file_done", p;
	}

# @TEST-END-FILE test.zeek

# Delay every record by 1msec.
event zeek_init()
	{
	Log::create_stream(LOG, [
		$columns=Info,
		$path="test",
		$policy=log_policy,
		$max_delay_interval=1msec,
	]);
	}

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id, rec;

	Log::delay(id, rec, function[now](rec2: Info, id2: Log::ID): bool {
		local delayed_for = network_time() - now;
		rec2$post_ts = network_time();
		print network_time(), "post_delay_cb", rec2, delayed_for;
		return T;
	});

	}

# # @TEST-START-NEXT
#
# Delay every record, but call Log::delay_finish() immediately afterwards
# through an event.

event zeek_init()
	{
	Log::create_stream(LOG, [
		$columns=Info,
		$path="test",
		$policy=log_policy,
		$max_delay_interval=1msec,
	]);
	}

event release_delay(rec: Info, token: Log::DelayToken)
	{
	Log::delay_finish(LOG, rec, token);
	}

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id;

	local token = Log::delay(id, rec, function[now](rec2: Info, id2: Log::ID): bool {
		local delayed_for = network_time() - now;
		rec2$post_ts = network_time();
		print network_time(), "post_delay_cb", rec2, delayed_for;
		return T;
	});

	event release_delay(rec, token);
	}

# # @TEST-START-NEXT
#
# Delay every record, and for every other record call Log::delay_finish()
# immediately afterwards via an event.

event zeek_init()
	{
	Log::create_stream(LOG, [
		$columns=Info,
		$path="test",
		$policy=log_policy,
		$max_delay_interval=1msec,
	]);
	}

event release_delay(rec: Info, token: Log::DelayToken)
	{
	Log::delay_finish(LOG, rec, token);
	}

global write = 0;

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	++write;

	local now = network_time();

	print now, "log_stream_policy", id;

	local token = Log::delay(id, rec, function[now](rec2: Info, id2: Log::ID): bool {
		local delayed_for = network_time() - now;
		rec2$post_ts = network_time();
		print network_time(), "post_delay_cb", rec2, delayed_for;
		return T;
	});

	if ( write % 2 == 1 )
		event release_delay(rec, token);

	}

# # @TEST-START-NEXT

# Delay every entry by 10 seconds, but set queue size to 5 such that
# entries are evicted when the queue size is reached.

event zeek_init()
	{
	Log::create_stream(LOG, [
		$columns=Info,
		$path="test",
		$policy=log_policy,
		$max_delay_interval=10sec,
		$max_delay_queue_size=5,
	]);
	}

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id, rec;

	Log::delay(id, rec, function[now](rec2: Info, id2: Log::ID): bool {
		local delayed_for = network_time() - now;
		rec2$post_ts = network_time();
		print network_time(), "post_delay_cb", rec2, delayed_for;
		return T;
	});
	}


# # @TEST-START-NEXT

# Re-delaying works even if that results in more forceful expiration.
redef record Info += {
	redelayed: bool &default=F;
};

event zeek_init()
	{
	Log::create_stream(LOG, [
		$columns=Info,
		$path="test",
		$policy=log_policy,
		$max_delay_interval=10sec,
		$max_delay_queue_size=5,
	]);
	}

function post_delay_cb(rec: Info, id: Log::ID): bool
	{
	if ( ! rec$redelayed )
		{
		print network_time(), "post_delay_cb - re-delay", rec;
		rec$post_ts = network_time();
		rec$redelayed = T;
		Log::delay(id, rec, post_delay_cb);
		return T;
		}


	print network_time(), "post_delay_cb - done", rec;
	return T;
	}

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id, rec;

	Log::delay(id, rec, post_delay_cb);
	}

# # @TEST-START-NEXT

# Re-delay once after the delay expired.
redef record Info += {
	redelayed: bool &default=F;
};

event zeek_init()
	{
	Log::create_stream(LOG, [
		$columns=Info,
		$path="test",
		$policy=log_policy,
		$max_delay_interval=1msec,
	]);
	}

function post_delay_cb(rec: Info, id: Log::ID): bool
	{
	if ( ! rec$redelayed )
		{
		print network_time(), "post_delay_cb - re-delay", rec;
		rec$post_ts = network_time();
		rec$redelayed = T;
		Log::delay(id, rec, post_delay_cb);
		return T;
		}


	print network_time(), "post_delay_cb - done", rec;
	return T;
	}

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id, rec;

	Log::delay(id, rec, post_delay_cb);
	}

# # @TEST-START-NEXT

# Re-delay once after Log::delay_finish()
redef record Info += {
	redelayed: bool &default=F;
};

event release_delay(rec: Info, token: Log::DelayToken)
	{
	Log::delay_finish(LOG, rec, token);
	}


event zeek_init()
	{
	Log::create_stream(LOG, [
		$columns=Info,
		$path="test",
		$policy=log_policy,
		$max_delay_interval=1msec,
	]);
	}

function post_delay_cb(rec: Info, id: Log::ID): bool
	{
	if ( ! rec$redelayed )
		{
		print network_time(), "post_delay_cb - re-delay", rec;
		rec$post_ts = network_time();
		rec$redelayed = T;
		local token = Log::delay(id, rec, post_delay_cb);

		event release_delay(rec, token);
		return T;
		}


	print network_time(), "post_delay_cb - done", rec;
	return T;
	}

hook Log::log_stream_policy(rec: Info, id: Log::ID)
	{
	if ( id != LOG )
		return;

	local now = network_time();

	print now, "log_stream_policy", id, rec;

	local token = Log::delay(id, rec, post_delay_cb);

	event release_delay(rec, token);
	}
